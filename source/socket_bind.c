#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "byte.h"
#include "socket.h"
#include "error.h"
#include "ip.h"
#include "ip4.h"
#include "ip6.h"

static int socket_bind4(int s,const char ip[IP4_LEN],uint16 port)
{
  struct sockaddr_in sa;

  byte_zero(&sa,sizeof sa);
#if defined(SIN6_LEN)	// sic!
  sa.sin_len = sizeof sa;
#endif
  sa.sin_family = AF_INET;
  uint16_pack_big((char *) &sa.sin_port,port);
  byte_copy(&sa.sin_addr,4,ip);

  return bind(s,(const struct sockaddr *) &sa,sizeof sa);
}

static int socket_bind4_reuse(int s,const char ip[IP4_LEN],uint16 port)
{
  int opt = 1;
  setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof opt);
  return socket_bind4(s,ip,port);
}

static int socket_bind6(int s,const char ip[IP6_LEN],uint16 port)
{
  struct sockaddr_in6 sa;

  byte_zero(&sa,sizeof sa);
#if defined(SIN6_LEN)
  sa.sin6_len = sizeof sa;
#endif
  sa.sin6_family = AF_INET6;
  uint16_pack_big((char *) &sa.sin6_port,port);
  byte_copy(&sa.sin6_addr,IP6_SANS_SCOPE_LEN,ip);
  byte_copy(&sa.sin6_scope_id,IP6_SCOPE_ID_LEN,ip+IP6_SANS_SCOPE_LEN);

  return bind(s,(struct sockaddr *) &sa,sizeof sa);
}

static int socket_bind6_reuse(int s,const char ip[IP6_LEN],uint16 port)
{
  int opt = 1;
  setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof opt);
  return socket_bind6(s,ip,port);
}

int socket_bind(int s,const struct ip_address * ip,uint16 port)
{
  switch (ip->len) {
    case IP4_LEN:	return socket_bind4(s,ip->d4,port);
    case IP6_LEN:	return socket_bind6(s,ip->d6,port);
    default:  errno = error_proto; return -1;
  }
}

int socket_bind_reuse(int s,const struct ip_address * ip,uint16 port)
{
  switch (ip->len) {
    case IP4_LEN:	return socket_bind4_reuse(s,ip->d4,port);
    case IP6_LEN:	return socket_bind6_reuse(s,ip->d6,port);
    default:  errno = error_proto; return -1;
  }
}

void socket_tryreservein(int s,int size)
{
  while (size >= 1024) {
    if (setsockopt(s,SOL_SOCKET,SO_RCVBUF,&size,sizeof size) == 0) return;
    size -= (size >> 5);
  }
}
