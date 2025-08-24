#include "byte.h"
#include "fmt.h"
#include "ip.h"
#include "ip4.h"
#include "ip6.h"
#include "dns_nd.h"
#include "error.h"

void dns_name4_ldomain(char name[DNS_NAME4_LDOMAIN],const char ip[IP4_LEN])
{
  unsigned int namelen;
  unsigned int i;

  namelen = 0;
  i = fmt_ulong(name + namelen + 1,(unsigned long) (unsigned char) ip[3]);
  name[namelen++] = i;
  namelen += i;
  i = fmt_ulong(name + namelen + 1,(unsigned long) (unsigned char) ip[2]);
  name[namelen++] = i;
  namelen += i;
  i = fmt_ulong(name + namelen + 1,(unsigned long) (unsigned char) ip[1]);
  name[namelen++] = i;
  namelen += i;
  i = fmt_ulong(name + namelen + 1,(unsigned long) (unsigned char) ip[0]);
  name[namelen++] = i;
  namelen += i;
  byte_copy(name + namelen,11,"\011localhost");
}

void dns_name4_domain(char name[DNS_NAME4_DOMAIN],const char ip[IP4_LEN])
{
  unsigned int namelen;
  unsigned int i;

  namelen = 0;
  i = fmt_ulong(name + namelen + 1,(unsigned long) (unsigned char) ip[3]);
  name[namelen++] = i;
  namelen += i;
  i = fmt_ulong(name + namelen + 1,(unsigned long) (unsigned char) ip[2]);
  name[namelen++] = i;
  namelen += i;
  i = fmt_ulong(name + namelen + 1,(unsigned long) (unsigned char) ip[1]);
  name[namelen++] = i;
  namelen += i;
  i = fmt_ulong(name + namelen + 1,(unsigned long) (unsigned char) ip[0]);
  name[namelen++] = i;
  namelen += i;
  byte_copy(name + namelen,14,"\007in-addr\004arpa");
}

void dns_name6_domain(char name[DNS_NAME6_DOMAIN],const char ip[IP6_LEN])
{
  unsigned int namelen;
  int j;

  namelen = 0;
  for (j = 16; j-- > 0; ) {
    name[namelen++] = '\1'; name[namelen++] = fmt_xdigit(ip[j] & 15U);
    name[namelen++] = '\1'; name[namelen++] = fmt_xdigit(ip[j] / 16U);
  }
  byte_copy(name + namelen,10,"\003ip6\004arpa");
}

int dns_name_domain(char name[DNS_NAME_DOMAIN],const struct ip_address * ip)
{
  switch (ip->len) {
    case IP4_LEN:	dns_name4_domain(name,ip->d4); return 0;
    case IP6_LEN:	dns_name6_domain(name,ip->d6); return 0;
    default:  errno = error_proto; return -1;
  }
}
