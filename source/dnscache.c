#include <unistd.h>
#include "env.h"
#include "exit.h"
#include "scan.h"
#include "strerr.h"
#include "error.h"
#include "ip.h"
#include "uint16.h"
#include "uint64.h"
#include "socket.h"
#include "dns_transmit.h"
#include "dns_random.h"
#include "dns_packet.h"
#include "taia.h"
#include "byte.h"
#include "roots.h"
#include "fmt.h"
#include "iopause.h"
#include "query.h"
#include "alloc.h"
#include "response.h"
#include "cache.h"
#include "ndelay.h"
#include "log.h"
#include "okclient.h"
#include "droproot.h"
#include "dnscache.h"

static int packetquery(char *buf,unsigned int len,char **q,char qtype[2],char qclass[2],char id[2],uint16 *max_response)
{
  unsigned int pos;
  char header[HEADER_SIZE];
  uint16 numquery;
  uint16 numanswer;
  uint16 numauthority;
  uint16 numglue;
  unsigned int j;

  errno = error_proto;
  pos = dns_packet_copy(buf,len,0,header,HEADER_SIZE); if (!pos) return 0;
  if (header[2] & 128) return 0;	/* must not respond to responses */
  if (!(header[2] & 1)) return 0;	/* do not respond to non-recursive queries */
  if (header[2] & 120) return 0;	/* do not respond to OPCODE != 0 (forward query) */
  if (header[2] & 2) return 0;		/* do not respond when TC = 1 */

  uint16_unpack_big(header + HEADER_QUERY,&numquery);
  if (1 != numquery) return 0;
  uint16_unpack_big(header + HEADER_ANSWER,&numanswer);
  if (numanswer) return 0;
  uint16_unpack_big(header + HEADER_AUTHORITY,&numauthority);
  if (numauthority) return 0;
  uint16_unpack_big(header + HEADER_ADDITIONAL,&numglue);
  if (numglue > 1) return 0;

  pos = dns_packet_getname(buf,len,pos,q); if (!pos) return 0;
  pos = dns_packet_copy(buf,len,pos,qtype,2); if (!pos) return 0;
  pos = dns_packet_copy(buf,len,pos,qclass,2); if (!pos) return 0;
  if (!dns_packet_internetclass(qclass)) return 0;
  byte_copy(id,2,header);

  *max_response = 512;
  for (j = 0;j < numglue;++j) {
    uint16 udpsize;
    uint16 datalen;
    char rrfixed[RRFIXED_SIZE];
    pos = dns_packet_skipname(buf,len,pos); if (!pos) return 0;
    pos = dns_packet_copy(buf,len,pos,rrfixed,RRFIXED_SIZE); if (!pos) return 0;
    uint16_unpack_big(rrfixed + RRFIXED_DATALEN,&datalen);
    if (!dns_packet_rrtypematch(rrfixed,DNS_T_OPT)) return 0;
    uint16_unpack_big(rrfixed + RRFIXED_CLASS,&udpsize);
    /* The 512 octet floor is obvious, but RFC 6891 explicitly states it too. */
    if (udpsize > 512 && udpsize <= MAX_RESPONSE) *max_response = udpsize;
    pos += datalen;
  }

  return 1;
}


static struct ip_address myipoutgoing = IP_ADDRESS_INIT;
static struct ip_address myipincoming = IP_ADDRESS_INIT;
static char buf[1024];
uint64 numqueries = 0;
static uint16 myportincoming = 53;  /* DNS */


#define MAXUDP 200
static struct udpclient {
  struct query q;
  struct taia start;
  uint64 active; /* query number, if active; otherwise 0 */
  iopause_fd *io;
  struct ip_address ip;
  uint16 port;
  uint16 max_response;
  char id[2];
} u[MAXUDP];
int uactive = 0;

static void u_drop(int j)
{
  if (!u[j].active) return;
  log_querydrop(&u[j].active);
  u[j].active = 0; --uactive;
}

static void u_respond(int udp53,int j)
{
  if (!u[j].active) return;
  response_id(u[j].id);
  if (response_len > u[j].max_response) response_tc();
  socket_send(udp53,response,response_len,&u[j].ip,u[j].port);
  log_querydone(&u[j].active,response_len);
  u[j].active = 0; --uactive;
}

static void u_new(int udp53)
{
  int j;
  int i;
  struct udpclient *x;
  int len;
  static char *q = 0;
  char qtype[2];
  char qclass[2];

  for (j = 0;j < MAXUDP;++j)
    if (!u[j].active)
      break;

  if (j >= MAXUDP) {
    j = 0;
    for (i = 1;i < MAXUDP;++i)
      if (taia_less(&u[i].start,&u[j].start))
	j = i;
    errno = error_timeout;
    u_drop(j);
  }

  x = u + j;
  taia_now(&x->start);

  len = socket_recv(udp53,buf,sizeof buf,&x->ip,&x->port);
  if (len == -1) return;
  if (len >= sizeof buf) return;
  if (x->port < 1024) if (x->port != 53) return;
  if (!okclient(&x->ip)) return;

  if (!packetquery(buf,len,&q,qtype,qclass,x->id,&x->max_response)) return;

  x->active = ++numqueries; ++uactive;
  log_query(&x->active,&x->ip,x->port,x->id,q,qtype,x->max_response);
  switch(query_start(&x->q,q,qtype,qclass,&myipoutgoing)) {
    case -1: u_drop(j); return;
    case 1: u_respond(udp53,j); break;
  }
}


#define MAXTCP 20
static struct tcpclient {
  struct query q;
  struct taia start;
  struct taia timeout;
  uint64 active; /* query number or 1, if active; otherwise 0 */
  iopause_fd *io;
  struct ip_address ip; /* send response to this address */
  uint16 port; /* send response to this port */
  char id[2];
  int tcp; /* open TCP socket, if active */
  int state;
  char *buf; /* 0, or dynamically allocated of length len */
  unsigned int len;
  unsigned int pos;
} t[MAXTCP];
int tactive = 0;

/*
state 1: buf 0; normal state at beginning of TCP connection
state 2: buf 0; have read 1 byte of query packet length into len
state 3: buf allocated; have read pos bytes of buf
state 0: buf 0; handling query in q
state -1: buf allocated; have written pos bytes
*/

static void t_free(int j)
{
  if (!t[j].buf) return;
  alloc_free(t[j].buf);
  t[j].buf = 0;
}

static void t_timeout(int j)
{
  struct taia now;
  if (!t[j].active) return;
  taia_now(&now);
  taia_uint(&t[j].timeout,10);
  taia_add(&t[j].timeout,&t[j].timeout,&now);
}

static void t_close(int j)
{
  if (!t[j].active) return;
  t_free(j);
  log_tcpclose(&t[j].ip,t[j].port);
  close(t[j].tcp);
  t[j].active = 0; --tactive;
}

static void t_drop(int j)
{
  log_querydrop(&t[j].active);
  errno = error_pipe;
  t_close(j);
}

static void t_respond(int j)
{
  if (!t[j].active) return;
  log_querydone(&t[j].active,response_len);
  response_id(t[j].id);
  t[j].len = response_len + 2;
  t_free(j);
  t[j].buf = alloc(response_len + 2);
  if (!t[j].buf) { t_close(j); return; }
  uint16_pack_big(t[j].buf,response_len);
  byte_copy(t[j].buf + 2,response_len,response);
  t[j].pos = 0;
  t[j].state = -1;
}

static void t_rw(int j)
{
  struct tcpclient *x;
  char ch;
  static char *q = 0;
  char qtype[2];
  char qclass[2];
  int r;
  uint16 max_response;

  x = t + j;
  if (x->state == -1) {
    r = write(x->tcp,x->buf + x->pos,x->len - x->pos);
    if (r <= 0) { t_close(j); return; }
    x->pos += r;
    if (x->pos == x->len) {
      t_free(j);
      x->state = 1; /* could drop connection immediately */
    }
    return;
  }

  r = read(x->tcp,&ch,1);
  if (r == 0) { errno = error_pipe; t_close(j); return; }
  if (r < 0) { t_close(j); return; }

  if (x->state == 1) {
    x->len = (unsigned char) ch;
    x->len <<= 8;
    x->state = 2;
    return;
  }
  if (x->state == 2) {
    x->len += (unsigned char) ch;
    if (!x->len) { errno = error_proto; t_close(j); return; }
    x->buf = alloc(x->len);
    if (!x->buf) { t_close(j); return; }
    x->pos = 0;
    x->state = 3;
    return;
  }

  if (x->state != 3) return; /* impossible */

  x->buf[x->pos++] = ch;
  if (x->pos < x->len) return;

  if (!packetquery(x->buf,x->len,&q,qtype,qclass,x->id,&max_response)) { t_close(j); return; }

  x->active = ++numqueries;
  log_query(&x->active,&x->ip,x->port,x->id,q,qtype,max_response);
  switch(query_start(&x->q,q,qtype,qclass,&myipoutgoing)) {
    case -1: t_drop(j); return;
    case 1: t_respond(j); return;
  }
  t_free(j);
  x->state = 0;
}

static void t_new(int tcp53)
{
  int i;
  int j;
  struct tcpclient *x;

  for (j = 0;j < MAXTCP;++j)
    if (!t[j].active)
      break;

  if (j >= MAXTCP) {
    j = 0;
    for (i = 1;i < MAXTCP;++i)
      if (taia_less(&t[i].start,&t[j].start))
	j = i;
    errno = error_timeout;
    if (t[j].state == 0)
      t_drop(j);
    else
      t_close(j);
  }

  x = t + j;
  taia_now(&x->start);

  x->tcp = socket_accept(tcp53,&x->ip,&x->port);
  if (x->tcp == -1) return;
  if (x->port < 1024) if (x->port != 53) { close(x->tcp); return; }
  if (!okclient(&x->ip)) { close(x->tcp); return; }
  if (ndelay_on(x->tcp) == -1) { close(x->tcp); return; } /* Linux bug */

  x->active = 1; ++tactive;
  x->state = 1;
  t_timeout(j);

  log_tcpopen(&x->ip,x->port);
}

static void doit(int udp53, int tcp53)
{
  iopause_fd io[3 + MAXUDP + MAXTCP];

  for (;;) {
    iopause_fd *udp53io;
    iopause_fd *tcp53io;
    struct taia deadline;
    struct taia stamp;
    int iolen = 0;
    unsigned int j;
    int r;

    taia_now(&stamp);
    taia_uint(&deadline,120);
    taia_add(&deadline,&deadline,&stamp);

    udp53io = io + iolen++;
    udp53io->fd = udp53;
    udp53io->events = IOPAUSE_READ;

    tcp53io = io + iolen++;
    tcp53io->fd = tcp53;
    tcp53io->events = IOPAUSE_READ;

    for (j = 0;j < MAXUDP;++j)
      if (u[j].active) {
	u[j].io = io + iolen++;
	query_io(&u[j].q,u[j].io,&deadline);
      }
    for (j = 0;j < MAXTCP;++j)
      if (t[j].active) {
	t[j].io = io + iolen++;
	if (t[j].state == 0)
	  query_io(&t[j].q,t[j].io,&deadline);
	else {
	  if (taia_less(&t[j].timeout,&deadline)) deadline = t[j].timeout;
	  t[j].io->fd = t[j].tcp;
	  t[j].io->events = (t[j].state > 0) ? IOPAUSE_READ : IOPAUSE_WRITE;
	}
      }

    iopause(io,iolen,&deadline,&stamp);

    for (j = 0;j < MAXUDP;++j)
      if (u[j].active) {
	r = query_get(&u[j].q,u[j].io,&stamp);
	if (r == -1) u_drop(j);
	if (r == 1) u_respond(udp53,j);
      }

    for (j = 0;j < MAXTCP;++j)
      if (t[j].active) {
	if (t[j].io->revents)
	  t_timeout(j);
	if (t[j].state == 0) {
	  r = query_get(&t[j].q,t[j].io,&stamp);
	  if (r == -1) t_drop(j);
	  if (r == 1) t_respond(j);
	}
	else
	  if (t[j].io->revents || taia_less(&t[j].timeout,&stamp))
	    t_rw(j);
      }

    if (udp53io)
      if (udp53io->revents)
	u_new(udp53);

    if (tcp53io)
      if (tcp53io->revents)
	t_new(tcp53);
  }
}

#define FATAL "dnscache: fatal: "

static char seed[128];

int main(void)
{
  char *x;
  unsigned long cachesize;
  int do_listen, do_udp_options;
  int udp53 = -1;
  int tcp53 = -1;

  udp53 = tcp53 = -1;
  do_listen = do_udp_options = 1;
  socket_listen_get_udptcp(FATAL,&udp53,&tcp53,&do_listen,&do_udp_options,&myportincoming,&myipincoming,myportincoming);

  droproot(FATAL);

  if (do_udp_options)
    socket_tryreservein(udp53,131072);

  byte_zero(seed,sizeof seed);
  read(0,seed,sizeof seed);
  dns_random_init(seed);
  close(0);

  x = env_get("IPSEND");
  if (x)
    if (!ip_scan(x,&myipoutgoing,':'))
      strerr_die3x(111,FATAL,"unable to parse IP address ",x);

  x = env_get("CACHESIZE");
  if (!x)
    strerr_die2x(111,FATAL,"$CACHESIZE not set");
  scan_ulong(x,&cachesize);
  if (!cache_init(cachesize))
    strerr_die3x(111,FATAL,"not enough memory for cache of size ",x);

  if (env_get("HIDETTL"))
    response_hidettl();
  if (env_get("FORWARDONLY"))
    query_forwardonly();
  else if (env_get("FORWARDFIRST"))
    query_forwardfirst();

  if (!roots_init())
    strerr_die2sys(111,FATAL,"unable to read servers: ");

  if (do_listen)
    if (socket_listen(tcp53,20) == -1)
      strerr_die2sys(111,FATAL,"unable to listen on TCP socket: ");

  log_startup();
  doit(udp53,tcp53);
  /*NOTREACHED*/ return 0;
}
