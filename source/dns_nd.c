#include "byte.h"
#include "fmt.h"
#include "dns.h"

void dns_name4_domain(char name[DNS_NAME4_DOMAIN],const char ip[4])
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
  byte_copy(name + namelen,14,"\7in-addr\4arpa\0");
}

void dns_name6_domain(char name[DNS_NAME6_DOMAIN],const char ip[16])
{
  unsigned int namelen;
  int j;

  namelen = 0;
  for (j = 16; j-- > 0; ) {
    name[namelen++] = '\1'; name[namelen++] = fmt_xdigit(ip[j] & 15U); 
    name[namelen++] = '\1'; name[namelen++] = fmt_xdigit(ip[j] / 16U); 
  }
  byte_copy(name + namelen,10,"\3ip6\4arpa\0");
}
