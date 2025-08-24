#include <sys/types.h>
#include <sys/time.h>
#include <sys/param.h>
#include "strerr.h"
#include "ip.h"
#include "socket.h"
#include "str.h"
#include "mem.h"
#include "substdio.h"
#include "readwrite.h"
#include "select.h"
#include "taia.h"

static char outbuf[16];
static substdio ssout = SUBSTDIO_FDBUF(write,1,outbuf,sizeof outbuf);

#define FATAL "taiclock: fatal: "
#define WARNING "taiclock: warning: "

void die_usage()
{
  strerr_die1x(100,"taiclock: usage: taiclock ip.ad.dr.ess");
}

static const char *host;
static struct ip_address ipremote;
static uint16 portremote = 4014;  /* TAICLOCK */
static int s;

static char initdeltaoffset[] = {0,0,0,0,0,2,163,0,0,0,0,0,0,0,0,0};
static char initdeltamin[] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
static char initdeltamax[] = {0,0,0,0,0,5,70,0,0,0,0,0,0,0,0,0};
static char initerrmin[] = {255,255,255,255,255,255,255,254,0,0,0,0,0,0,0,0};
static char initerrmax[] = {0,0,0,0,0,0,0,2,0,0,0,0,0,0,0,0};
static struct taia deltaoffset;
static struct taia deltamin;
static struct taia deltamax;
static struct taia errmin;
static struct taia errmax;

static struct taia ta0;
static struct taia ta1;

static unsigned char query[32];
static unsigned char response[32];
static struct taia taremote;

static struct taia temp1;
static struct taia temp2;

static unsigned char adj[16];

int main(int argc,char ** argv)
{
  struct timeval tvselect;
  fd_set rfds;
  unsigned long u;
  int r;
  int loop;
  (void)argc;	/* Silence a compiler warning. */

  taia_unpack(initdeltamin,&deltamin);
  taia_unpack(initdeltamax,&deltamax);
  taia_unpack(initdeltaoffset,&deltaoffset);
  taia_unpack(initerrmin,&errmin);
  taia_unpack(initerrmax,&errmax);

  host = argv[1];
  if (!host) die_usage();
  if (!str_diff(host,"0")) host = "127.0.0.1";
  if (host[ip_scan(host,&ipremote,':')]) die_usage();

  s = socket_udp(&ipremote);
  if (s == -1)
    strerr_die2sys(111,FATAL,"unable to create socket: ");
#if 0
  if (socket_connect(s,&ipremote,portremote) == -1)
    strerr_die2sys(111,FATAL,"unable to connect socket: ");
#endif

  for (loop = 0;loop < 10;++loop) {
    uint16 dummy2;
    struct ip_address dummy1 = IP_ADDRESS_INIT;

    mem_zero(query,sizeof query);
    query[0] = 'c';
    query[1] = 't';
    query[2] = 'a';
    query[3] = 'i';

    /* XXX: cookie-building time */
    taia_now(&ta0);
    taia_pack(query + 16,&ta0);
    u = getpid();
    query[30] = u; u >>= 8;
    query[31] = u;

    taia_now(&ta0);
    if (socket_send(s,query,sizeof query,&ipremote,portremote) == -1)
      strerr_die2sys(111,FATAL,"unable to send request: ");
    FD_ZERO(&rfds);
    FD_SET(s,&rfds);
    tvselect.tv_sec = 1;
    tvselect.tv_usec = 0;
    if (select(s + 1,&rfds,(fd_set *) 0,(fd_set *) 0,&tvselect) != 1) {
      strerr_warn2(WARNING,"unable to read clock: timed out",0);
      continue;
    }
    r = socket_recv(s,response,sizeof response,&dummy1,&dummy2);
    if (r == -1) {
      strerr_warn2(WARNING,"unable to read clock: ",&strerr_sys);
      continue;
    }
    taia_now(&ta1);
    if (   (r != sizeof response)
	|| (response[0] != 's')
	|| mem_diff(query + 1,3,response + 1)
	|| mem_diff(query + 20,12,response + 20)
       ) {
      strerr_warn2(WARNING,"unable to read clock: bad response format",0);
      continue;
    }

    taia_unpack(response + 4,&taremote);
    taia_add(&taremote,&taremote,&deltaoffset);

    taia_add(&temp1,&deltamax,&ta0);
    taia_add(&temp2,&deltamin,&ta0);
    if (taia_less(&taremote,&temp1) && !taia_less(&taremote,&temp2)) {
      taia_sub(&temp1,&taremote,&ta0);
      deltamax = temp1;
    }
    taia_add(&temp1,&deltamax,&ta1);
    taia_add(&temp2,&deltamin,&ta1);
    if (taia_less(&temp2,&taremote) && !taia_less(&temp1,&taremote)) {
      taia_sub(&temp2,&taremote,&ta1);
      deltamin = temp2;
    }
  }

  taia_sub(&temp1,&deltamax,&deltamin);
  if (taia_less(&errmax,&temp1) && taia_less(&temp1,&errmin))
    strerr_die2x(111,FATAL,"time uncertainty too large");

  taia_add(&temp1,&deltamax,&deltamin);
  taia_half(&temp1,&temp1);
  taia_sub(&temp1,&temp1,&deltaoffset);

  taia_pack(adj,&temp1);

  if (substdio_putflush(&ssout,adj,sizeof adj) == -1)
    strerr_die2sys(111,FATAL,"unable to write output: ");
  return 0;
}
