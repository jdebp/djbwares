#include <sys/types.h>
#include <sys/time.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include "taia.h"
#include "byte.h"
#include "env.h"
#include "scan.h"
#include "strerr.h"
#include "uint16.h"
#include "socket.h"
#include "ndelay.h"

#define FATAL "taiclockd: fatal: "

char packet[256];
static char ip[4];
static uint16 port;
struct taia ta;

int main(int argc,char ** argv)
{
  char *x;
  int s;
  (void)argc;	/* Silence a compiler warning. */
  (void)argv;	/* Silence a compiler warning. */

  s = -1;
  x = env_get("LISTEN_PID");
  if (x) {
    int pid, fd, len;
    unsigned long i;

    pid = getpid();
    len = scan_ulong(x, &i);

    if (len && !x[len] && pid == i) {
      x = env_get("LISTEN_FDS");
      if (x) {
        len = scan_ulong(x, &i);

        if (len && !x[len]) {
          unsigned int o;

          for (o = 0U; o < i; ++o) {
            fd = 3 + o;
            if (socket_is_udp4(fd)) {
              if (0 > socket_local4(fd,ip,&port))
                strerr_die2sys(111,FATAL,"unable to get local address from UDP socket: ");
              s = fd;
            }
          }
        }
      }
    }
  }

  if (s == -1) {
    s = socket_udp();
    if (s == -1)
      strerr_die2sys(111,FATAL,"unable to create UDP socket: ");
    if (socket_bind4_reuse(s,ip,4014) == -1)
      strerr_die2sys(111,FATAL,"unable to bind UDP socket: ");
    ndelay_off(s);
  }

  for (;;) {
    int r;

    r = socket_recv4(s,packet,sizeof packet,ip,&port);
    if (r < 0) continue;
    if (r >= 20)
      if (!byte_diff(packet,4,"ctai")) {
	packet[0] = 's';
        taia_now(&ta);
        taia_pack(packet + 4,&ta);
        socket_send4(s,packet,r,ip,port);
        /* if it fails, bummer */
      }
  }
}
