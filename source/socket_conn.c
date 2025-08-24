#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include "mem.h"
#include "socket.h"
#include "ip.h"
#include "ip4.h"
#include "ip6.h"
#include "error.h"

static int socket_connect4(int s,const char ip[IP4_LEN],uint16 port)
{
  struct sockaddr_in sa;

  mem_zero(&sa,sizeof sa);
#if defined(SIN6_LEN)	// sic!
  sa.sin_len = sizeof sa;
#endif
  sa.sin_family = AF_INET;
  uint16_pack_big((char *) &sa.sin_port,port);
  mem_copy(&sa.sin_addr,4,ip);

  return connect(s,(struct sockaddr *) &sa,sizeof sa);
}

static int socket_connect6(int s,const char ip[IP6_LEN],uint16 port)
{
  struct sockaddr_in6 sa;

  mem_zero(&sa,sizeof sa);
#if defined(SIN6_LEN)
  sa.sin6_len = sizeof sa;
#endif
  sa.sin6_family = AF_INET6;
  uint16_pack_big((char *) &sa.sin6_port,port);
  mem_copy(&sa.sin6_addr,IP6_SANS_SCOPE_LEN,ip);
  mem_copy(&sa.sin6_scope_id,IP6_SCOPE_ID_LEN,ip + IP6_SANS_SCOPE_LEN);

  return connect(s,(struct sockaddr *) &sa,sizeof sa);
}

int socket_connect(int s,const struct ip_address * ip,uint16 port)
{
  switch (ip->len) {
    case IP4_LEN:	return socket_connect4(s,ip->d4,port);
    case IP6_LEN:	return socket_connect6(s,ip->d6,port);
    default:  errno = error_proto; return -1;
  }
}

int socket_connected(int s)
{
  struct sockaddr_storage sa;
  socklen_t dummy = sizeof sa;
  char ch;

  if (getpeername(s,(struct sockaddr *) &sa,&dummy) == -1) {
    read(s,&ch,1); /* sets errno */
    return 0;
  }
  return 1;
}
