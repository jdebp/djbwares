#include "fmt.h"
#include "ip.h"
#include "ip4.h"
#include "ip6.h"

unsigned int ip_fmt(char * s,const struct ip_address * ip,char sep)
{
  switch (ip->len) {
    case IP4_LEN:  return ip4_fmt(s, (const char *)ip->d4);
    case IP6_LEN:  return ip6_fmt(s, (const char *)ip->d6, sep);
    default:  *s = '?'; return 1 + fmt_uint(s + 1,ip->len);
  }
}
