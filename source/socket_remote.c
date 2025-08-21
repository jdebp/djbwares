#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "byte.h"
#include "socket.h"
#include "ip.h"
#include "ip4.h"

extern int ip_make(struct ip_address * ip,const struct sockaddr_storage * ss,uint16 *port);

int socket_remote(int s,struct ip_address * ip,uint16 *port)
{
  struct sockaddr_storage ss;
  socklen_t dummy = sizeof ss;

  if (getpeername(s,(struct sockaddr *) &ss,&dummy) == -1) return -1;
  return ip_make(ip,&ss,port);
}
