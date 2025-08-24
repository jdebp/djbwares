#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "mem.h"
#include "socket.h"
#include "ip.h"
#include "ip4.h"
#include "ip6.h"
#include "error.h"

static int socket_send4(int s,const char *buf,int len,const char ip[IP4_LEN],uint16 port)
{
  struct sockaddr_in sa;

  mem_zero(&sa,sizeof sa);
  sa.sin_family = AF_INET;
  uint16_pack_big((char *) &sa.sin_port,port);
  mem_copy(&sa.sin_addr,4,ip);

  return sendto(s,buf,len,0,(struct sockaddr *) &sa,sizeof sa);
}

static int socket_send6(int s,const char *buf,int len,const char ip[IP6_LEN],uint16 port)
{
  struct sockaddr_in6 sa;

  mem_zero(&sa,sizeof sa);
  sa.sin6_family = AF_INET6;
  uint16_pack_big((char *) &sa.sin6_port,port);
  mem_copy(&sa.sin6_addr,IP6_SANS_SCOPE_LEN,ip);
  mem_copy(&sa.sin6_scope_id,IP6_SCOPE_ID_LEN,ip+IP6_SANS_SCOPE_LEN);

  return sendto(s,buf,len,0,(struct sockaddr *) &sa,sizeof sa);
}

int socket_send(int s,const char *buf,int len,const struct ip_address * ip,uint16 port)
{
  switch (ip->len) {
    case IP4_LEN:	return socket_send4(s,buf,len,ip->d4,port);
    case IP6_LEN:	return socket_send6(s,buf,len,ip->d6,port);
    default:  errno = error_proto; return -1;
  }
}
