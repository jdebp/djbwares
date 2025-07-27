#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "byte.h"
#include "socket.h"

int socket_recv4(int s,char *buf,int len,char ip[4],uint16 *port)
{
  struct sockaddr_in sa;
  socklen_t dummy = sizeof sa;
  int r;

  r = recvfrom(s,buf,len,0,(struct sockaddr *) &sa,&dummy);
  if (r == -1) return -1;

  byte_copy(ip,4,&sa.sin_addr);
  uint16_unpack_big((char *) &sa.sin_port,port);

  return r;
}

int socket_recv6(int s,char *buf,int len,char ip[20],uint16 *port)
{
  struct sockaddr_in6 sa;
  socklen_t dummy = sizeof sa;
  int r;

  r = recvfrom(s,buf,len,0,(struct sockaddr *) &sa,&dummy);
  if (r == -1) return -1;

  byte_copy(ip,16,&sa.sin6_addr);
  byte_copy(ip+16,4,&sa.sin6_scope_id);
  uint16_unpack_big((char *) &sa.sin6_port,port);

  return r;
}
