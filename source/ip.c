#include <sys/socket.h>
#include <netinet/in.h>
#include "ip.h"
#include "ip4.h"
#include "ip6.h"
#include "byte.h"
#include "uint16.h"
#include "uint32.h"
#include "error.h"

void ip_make_unassigned(struct ip_address * ip)
{
  ip->len = 0;
}

void ip_make_zero4(struct ip_address * ip)
{
  ip->len = IP4_LEN; byte_zero(ip->d4, IP4_LEN);
}

void ip_make_zero6(struct ip_address * ip)
{
  ip->len = IP6_LEN; byte_zero(ip->d6, IP6_LEN);
}

void ip_make4(struct ip_address * ip,const char a[IP4_LEN])
{
  ip->len = IP4_LEN; byte_copy(ip->d4, IP4_LEN, a);
}

void ip_make6(struct ip_address * ip,const char a[IP6_SANS_SCOPE_LEN],uint32 scope)
{
  ip->len = IP6_LEN; byte_copy(ip->d6, IP6_SANS_SCOPE_LEN, a); byte_copy(ip->d6 + IP6_SANS_SCOPE_LEN, 4, &scope);
}

int ip_make(struct ip_address * ip,const struct sockaddr_storage * ss,uint16 *port)
{
  uint32 scope;
  switch (ss->ss_family) {
    case AF_INET:
      ip_make4(ip,&((const struct sockaddr_in *)ss)->sin_addr);
      uint16_unpack_big((char *)&((const struct sockaddr_in *)ss)->sin_port,port);
      return 0;
    case AF_INET6:
      uint32_unpack_big((char *)&((const struct sockaddr_in6 *)ss)->sin6_scope_id,&scope);
      ip_make6(ip,&((const struct sockaddr_in6 *)ss)->sin6_addr,scope);
      uint16_unpack_big((char *)&((const struct sockaddr_in6 *)ss)->sin6_port,port);
      return 0;
    default:  errno = error_proto; return -1;
  }
}

void ip_make_loopback4(struct ip_address * ip)
{
  ip_make4(ip,"\177\0\0\1");
}

void ip_make_loopback6(struct ip_address * ip)
{
  ip_make6(ip,"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\1",0);
}

int ip_make_loopback(struct ip_address * ip)
{
  switch (ip->len) {
    case IP4_LEN:
      byte_copy(ip->d4, "\177\0\0\1", IP4_LEN);
      return 0;
    case IP6_LEN:
      byte_copy(ip->d6, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\1", IP6_LEN);
      return 0;
    default:  errno = error_proto; return -1;
  }
}

int ip_make_zero(struct ip_address * ip)
{
  switch (ip->len) {
    case IP4_LEN:
      byte_zero(ip->d4, IP4_LEN);
      return 0;
    case IP6_LEN:
      byte_zero(ip->d6, IP6_LEN);
      return 0;
    default:  errno = error_proto; return -1;
  }
}

int ip_is4(const struct ip_address * ip)
{
  return IP4_LEN == ip->len;
}

int ip_is6(const struct ip_address * ip)
{
  return IP6_LEN == ip->len;
}

int ip_is_unassigned(const struct ip_address * ip)
{
  return IP4_LEN != ip->len && IP6_LEN != ip->len;
}

int ip_is_zero(const struct ip_address * ip)
{
  switch (ip->len) {
    case IP4_LEN:	return byte_equal(ip->d4, IP4_LEN, "\0\0\0\0");
    case IP6_LEN:	return byte_equal(ip->d6, IP6_LEN, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
    default:  errno = error_proto; return 0;
  }
}

int ip_equals(const struct ip_address * ip1,const struct ip_address *ip2)
{
    if (ip1->len != ip2->len) return 0;
    return byte_equal(ip1->d6, ip1->len, ip2->d6);
}
