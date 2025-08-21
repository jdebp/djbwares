#include <sys/types.h>
#include "taia.h"
#include "byte.h"
#include "strerr.h"
#include "uint16.h"
#include "socket.h"
#include "ip.h"

#define FATAL "taiclockd: fatal: "

static char packet[256];
static struct ip_address iplocal = IP_ADDRESS_INIT;
static uint16 portlocal = 4014; /* TAICLOCK */
static struct taia ta;

int main(int argc,char ** argv)
{
  int udp, do_udp_options;
  if (argc > 1)
    strerr_die1x(100,"taiclockd: usage: taiclockd");
  (void)argv;	/* Silence a compiler warning. */

  udp = -1;
  do_udp_options = 1;
  socket_listen_get_udp(FATAL,&udp,&do_udp_options,&portlocal,&iplocal,portlocal);

  for (;;) {
    int r;
    uint16 portremote;
    struct ip_address ipremote = IP_ADDRESS_INIT;

    r = socket_recv(udp,packet,sizeof packet,&ipremote,&portremote);
    if (r < 0) continue;
    if (r >= 20)
      if (!byte_diff(packet,4,"ctai")) {
	packet[0] = 's';
        taia_now(&ta);
        taia_pack(packet + 4,&ta);
        socket_send(udp,packet,r,&ipremote,portremote);
        /* if it fails, bummer */
      }
  }
}
