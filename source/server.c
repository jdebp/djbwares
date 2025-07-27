#include "byte.h"
#include "case.h"
#include "buffer.h"
#include "strerr.h"
#include "ip4.h"
#include "uint16.h"
#include "socket.h"
#include "droproot.h"
#include "qlog.h"
#include "response.h"
#include "dns.h"
#include <unistd.h>

extern char *fatal;
extern char *starting;
extern int respond(char *,char *,char *);
extern void initialize(void);

static char ip[4];
static uint16 port;

static char buf[513];
static int len;

static char *q;

static int doit(void)
{
  unsigned int pos;
  char header[12];
  char qtype[2];
  char qclass[2];

  header[0] = header[1] = '\0';
  qtype[0] = qtype[1] = '\0';
  qclass[0] = qclass[1] = '\0';

  if (len >= sizeof buf) goto NOQ;
  pos = dns_packet_copy(buf,len,0,header,12); if (!pos) goto NOQ;
  if (header[2] & 128) goto NOQ;
  if (header[4]) goto NOQ;
  if (header[5] != 1) goto NOQ;

  pos = dns_packet_getname(buf,len,pos,&q); if (!pos) goto NOQ;
  pos = dns_packet_copy(buf,len,pos,qtype,2); if (!pos) goto NOQ;
  pos = dns_packet_copy(buf,len,pos,qclass,2); if (!pos) goto NOQ;

  if (!response_query(q,qtype,qclass)) goto NOQ;
  response_id(header);
  if (byte_equal(qclass,2,DNS_C_IN))
    response[2] |= 4;
  else
    goto WEIRDCLASS;
  response[3] &= ~128;
  if (!(header[2] & 1)) response[2] &= ~1;

  if (header[2] & 126) goto NOTIMP;
  if (byte_equal(qtype,2,DNS_T_AXFR)) goto NOTIMP;

  case_lowerb(q,dns_domain_length(q));
  if (!respond(q,qtype,ip)) {
    qlog(ip,port,header,q,qtype," - ");
    return 0;
  }
  qlog(ip,port,header,q,qtype," + ");
  return 1;

  NOTIMP:
  response[3] &= ~15;
  response[3] |= 4;
  qlog(ip,port,header,q,qtype," I ");
  return 1;

  WEIRDCLASS:
  response[3] &= ~15;
  response[3] |= 1;
  qlog(ip,port,header,q,qtype," C ");
  return 1;

  NOQ:
  qlog(ip,port,header,q,qtype," / ");
  return 0;
}

int main(void)
{
  int udp53, do_udp_options;

  udp53 = -1;
  do_udp_options = 1;
  socket_listen_get_udp4(fatal,&udp53,&do_udp_options,&port,ip,53);

  droproot(fatal);

  if (do_udp_options)
    socket_tryreservein(udp53,65536);

  initialize();

  buffer_putsflush(buffer_2,starting);

  if (!dns_domain_copy(&q,""))
      strerr_die2sys(111,fatal,"unable to initialize query-name buffer: ");

  for (;;) {
    len = socket_recv4(udp53,buf,sizeof buf,ip,&port);
    if (len < 0) continue;
    if (!doit()) continue;
    if (response_len > 512) response_tc();
    socket_send4(udp53,response,response_len,ip,port);
    /* may block for buffer space; if it fails, too bad */
  }
}
