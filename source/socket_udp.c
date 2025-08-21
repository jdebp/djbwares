#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include "ndelay.h"
#include "socket.h"
#include "ip.h"
#include "error.h"

static int socket_udp4(void)
{
  int s;

  s = socket(AF_INET,SOCK_DGRAM,0);
  if (s == -1) return -1;
  if (ndelay_on(s) == -1) { close(s); return -1; }
  return s;
}

static int socket_udp6(void)
{
  int s;

  s = socket(AF_INET6,SOCK_DGRAM,0);
  if (s == -1) return -1;
  if (ndelay_on(s) == -1) { close(s); return -1; }
  return s;
}

int socket_udp(const struct ip_address * ip)
{
  switch (ip->len) {
    case IP4_LEN:	return socket_udp4();
    case IP6_LEN:	return socket_udp6();
    default:  errno = error_proto; return -1;
  }
}
