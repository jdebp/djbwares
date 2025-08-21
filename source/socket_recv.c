#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "byte.h"
#include "socket.h"
#include "ip.h"
#include "ip4.h"
#include "ip6.h"

extern int ip_make(struct ip_address * ip,const struct sockaddr_storage * ss,uint16 *port);

int socket_recv(int s,char *buf,int len,struct ip_address * ip,uint16 *port)
{
  struct sockaddr_storage ss;
  socklen_t dummy = sizeof ss;
  int r;

  r = recvfrom(s,buf,len,0,(struct sockaddr *) &ss,&dummy);
  if (r == -1) return -1;

  ip_make(ip,&ss,port);

  return r;
}
