#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include "socket.h"

static int socket_is(int fd, int family1, int family2, int type) {
  struct stat s;
  struct sockaddr a = {};
  socklen_t al = sizeof(a);
  int t = 0;
  socklen_t tl = sizeof(t);

  if (fd < 0)
    return 0;
  if (fstat(fd, &s) < 0)
    return 0;
  if (!S_ISSOCK(s.st_mode))
    return 0;
  if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &t, &tl) < 0)
    return 0;
  if (tl != sizeof(t))
    return 0;
  if (t != type)
    return 0;
  if (getsockname(fd, &a, &al) < 0)
    return 0;
  if (al < sizeof(sa_family_t))
    return 0;
  if (a.sa_family != family1 && a.sa_family != family2)
    return 0;

  return 1;
}

int socket_is_udp(int fd) {
  return socket_is(fd, AF_INET, AF_INET6, SOCK_DGRAM);
}

int socket_is_tcp(int fd) {
  return socket_is(fd, AF_INET, AF_INET6, SOCK_STREAM);
}
