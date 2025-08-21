#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "byte.h"
#include "socket.h"
#include "ip.h"

extern int ip_make(struct ip_address * ip,const struct sockaddr_storage * ss,uint16 *port);

int socket_accept(int s,struct ip_address * ip,uint16 *port)
{
  struct sockaddr_storage ss;
  socklen_t dummy = sizeof ss;
  int fd;

  fd = accept(s,(struct sockaddr *) &ss,&dummy);
  if (fd == -1) return -1;

  ip_make(ip,&ss,port);

  return fd;
}
