#include <sys/types.h>
#include "taia.h"
#include "byte.h"
#include "strerr.h"
#include "uint16.h"
#include "socket.h"

#define FATAL "taiclock4d: fatal: "

static char packet[256];
static char ip[4];
static uint16 port;
static struct taia ta;

int main(int argc,char ** argv)
{
  int udp, do_udp_options;
  if (argc > 1)
    strerr_die1x(100,"taiclock4d: usage: taiclock4d");
  (void)argv;	/* Silence a compiler warning. */

  udp = -1;
  do_udp_options = 1;
  socket_listen_get_udp4(FATAL,&udp,&do_udp_options,&port,ip,4014);

  for (;;) {
    int r;

    r = socket_recv4(udp,packet,sizeof packet,ip,&port);
    if (r < 0) continue;
    if (r >= 20)
      if (!byte_diff(packet,4,"ctai")) {
	packet[0] = 's';
        taia_now(&ta);
        taia_pack(packet + 4,&ta);
        socket_send4(udp,packet,r,ip,port);
        /* if it fails, bummer */
      }
  }
}
