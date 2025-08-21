/* Public domain. */

#include <sys/types.h>
#include <unistd.h>
#include "error.h"
#include "strerr.h"
#include "scan.h"
#include "ip.h"
#include "env.h"
#include "socket.h"
#include "ndelay.h"
#include "uint16.h"

static int get_inherit_count(unsigned long * count)
{
  char * x;
  int pid, len;
  unsigned long i;

  x = env_get("LISTEN_PID");
  if (!x) return 0;
  pid = getpid();
  len = scan_ulong(x, &i);
  if (!len || x[len] || (unsigned long)pid != i) return 0;

  x = env_get("LISTEN_FDS");
  if (!x) return 0;
  len = scan_ulong(x, count);
  if (!len || x[len]) return 0;

  return 1;
}

static void socket_listen_inherit_udp(int * udpfd)
{
  unsigned long i;
  unsigned int o;

  if (!get_inherit_count(&i)) return;

  for (o = 0U; o < i; ++o) {
    int fd;
    fd = 3 + o;
    if (socket_is_udp(fd)) {
      *udpfd = fd;
      return;
    }
  }
}

void socket_listen_get_udp(const char * fatal, int * udpfd, int * do_udp_options, uint16 * port, struct ip_address * ip, uint16 defport)
{
  char * x;

  *udpfd = -1;
  *do_udp_options = 1;
  socket_listen_inherit_udp(udpfd);
  if (-1 != *udpfd) {
    if (0 > socket_local(*udpfd,ip,port))
      strerr_die2sys(111,fatal,"unable to get local address from listening socket: ");
    *do_udp_options = 0;
    return;
  }

  x = env_get("IP");
  if (!x)
    strerr_die2x(111,fatal,"$IP not set");
  if (!ip_scan(x,ip,':'))
    strerr_die3x(111,fatal,"unable to parse IP address ",x);

  *udpfd = socket_udp(ip);
  if (*udpfd == -1)
    strerr_die2sys(111,fatal,"unable to create UDP socket: ");
  if (socket_bind_reuse(*udpfd,ip,defport) == -1)
    strerr_die2sys(111,fatal,"unable to bind UDP socket: ");
  *port = defport;
  ndelay_off(*udpfd);
}

static void socket_listen_inherit_udptcp(int * udpfd, int * tcpfd)
{
  char * x;
  int pid, len;
  unsigned long i;
  unsigned int o;

  *udpfd = *tcpfd = -1;

  x = env_get("LISTEN_PID");
  if (!x) return;
  pid = getpid();
  len = scan_ulong(x, &i);
  if (!len || x[len] || (unsigned long)pid != i) return;

  x = env_get("LISTEN_FDS");
  if (!x) return;
  len = scan_ulong(x, &i);
  if (!len || x[len]) return;

  for (o = 0U; o < i; ++o) {
    int fd;
    fd = 3 + o;
    if (socket_is_udp(fd))
      *udpfd = fd;
    else
    if (socket_is_tcp(fd))
      *tcpfd = fd;
  }
}

void socket_listen_get_udptcp(const char * fatal, int * udpfd, int * tcpfd, int * do_listen, int * do_udp_options, uint16 * port, struct ip_address * ip, uint16 defport)
{
  char * x;

  *udpfd = *tcpfd = -1;
  *do_listen = *do_udp_options = 1;
  socket_listen_inherit_udptcp(udpfd,tcpfd);
  if (-1 != *udpfd && -1 != *tcpfd) {
    if (0 > socket_local(*udpfd,ip,port))
      strerr_die2sys(111,fatal,"unable to get local address from listening socket: ");
    *do_listen = *do_udp_options = 0;
    return;
  }

  x = env_get("IP");
  if (!x)
    strerr_die2x(111,fatal,"$IP not set");
  if (!ip_scan(x,ip,':'))
    strerr_die3x(111,fatal,"unable to parse IP address ",x);
  *port = defport;

  if (*udpfd == -1) {
    *udpfd = socket_udp(ip);
    if (*udpfd == -1)
      strerr_die2sys(111,fatal,"unable to create UDP socket: ");
    if (socket_bind_reuse(*udpfd,ip,defport) == -1)
      strerr_die2sys(111,fatal,"unable to bind UDP socket: ");
    ndelay_off(*udpfd);
  } else
    *do_udp_options = 0;

  if (*tcpfd == -1) {
    *tcpfd = socket_tcp(ip);
    if (*tcpfd == -1)
      strerr_die2sys(111,fatal,"unable to create TCP socket: ");
    if (socket_bind_reuse(*tcpfd,ip,defport) == -1)
      strerr_die2sys(111,fatal,"unable to bind TCP socket: ");
  } else
    *do_listen = 0;
}
