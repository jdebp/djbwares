#include "scan.h"
#include "uint16.h"
#include "str.h"
#include "ip.h"
#include "ip4.h"
#include "ip6.h"
#include "byte.h"

unsigned int ip4_scan_n(const char *s,unsigned int max,char ip[IP4_LEN])
{
  unsigned int i;
  unsigned int len;
  unsigned long u;
 
  len = 0;
  i = scan_ulong_n(s,max,&u); if (!i || u > 255U) return 0; ip[0] = u; s += i; len += i; max -= i;
  if (!max || *s != '.') return 0; ++s; ++len; --max;
  i = scan_ulong_n(s,max,&u); if (!i || u > 255U) return 0; ip[1] = u; s += i; len += i; max -= i;
  if (!max || *s != '.') return 0; ++s; ++len; --max;
  i = scan_ulong_n(s,max,&u); if (!i || u > 255U) return 0; ip[2] = u; s += i; len += i; max -= i;
  if (!max || *s != '.') return 0; ++s; ++len; --max;
  i = scan_ulong_n(s,max,&u); if (!i || u > 255U) return 0; ip[3] = u; s += i; len += i; max -= i;
  return len;
}

unsigned int ip4_scan(const char *s,char ip[IP4_LEN])
{
  return ip4_scan_n(s,str_len(s),ip);
}

static unsigned int ip6_scan_n(const char *s,unsigned int max,char ip[IP6_LEN],char sep)
{
  unsigned int i;
  unsigned int len;
  unsigned long u;
  char * a;
 
  len = 0;
  a = ip;
  i = scan_xlong_n(s,max,&u); if (!i || u > 0xFFFF) return 0; uint16_pack_big(a,u); s += i; len += i; a += 2; max -= i;
  if (!max || *s != sep) return 0; ++s; ++len; --max;
  i = scan_xlong_n(s,max,&u); if (!i || u > 0xFFFF) return 0; uint16_pack_big(a,u); s += i; len += i; a += 2; max -= i;
  if (!max || *s != sep) return 0; ++s; ++len; --max;
  i = scan_xlong_n(s,max,&u); if (!i || u > 0xFFFF) return 0; uint16_pack_big(a,u); s += i; len += i; a += 2; max -= i;
  if (!max || *s != sep) return 0; ++s; ++len; --max;
  i = scan_xlong_n(s,max,&u); if (!i || u > 0xFFFF) return 0; uint16_pack_big(a,u); s += i; len += i; a += 2; max -= i;
  if (!max || *s != sep) return 0; ++s; ++len; --max;
  i = scan_xlong_n(s,max,&u); if (!i || u > 0xFFFF) return 0; uint16_pack_big(a,u); s += i; len += i; a += 2; max -= i;
  if (!max || *s != sep) return 0; ++s; ++len; --max;
  i = scan_xlong_n(s,max,&u); if (!i || u > 0xFFFF) return 0; uint16_pack_big(a,u); s += i; len += i; a += 2; max -= i;
  if (!max || *s != sep) return 0; ++s; ++len; --max;
  i = scan_xlong_n(s,max,&u); if (!i || u > 0xFFFF) return 0; uint16_pack_big(a,u); s += i; len += i; a += 2; max -= i;
  if (!max || *s != sep) return 0; ++s; ++len; --max;
  i = scan_xlong_n(s,max,&u); if (!i || u > 0xFFFF) return 0; uint16_pack_big(a,u); s += i; len += i; a += 2; max -= i;
  return len;
}

unsigned int ip6_scan(const char *s,char ip[IP6_LEN],char sep)
{
  return ip6_scan_n(s,str_len(s),ip,sep);
}

unsigned int ip_scan_n(const char * s,unsigned int max,struct ip_address * ip,char sep)
{
  switch (ip->len) {
    case 0U: {
      unsigned int len;
      len = ip4_scan_n(s,max,(char *)ip->d4);
      if (0 < len) { ip->len = IP4_LEN; return len; }
      len = ip6_scan_n(s,max,(char *)ip->d6,sep);
      if (0 < len) { ip->len = IP6_LEN; return len; }
      return 0;
    }
    case IP4_LEN:  return ip4_scan_n(s,max,(char *)ip->d4);
    case IP6_LEN:  return ip6_scan_n(s,max,(char *)ip->d6,sep);
    default:  return 0;
  }
}

unsigned int ip_scan(const char * s,struct ip_address * ip,char sep)
{
  return ip_scan_n(s,str_len(s),ip,sep);
}

unsigned int ip_scanbracket(const char * s,struct ip_address * ip,char sep)
{
  unsigned int len;
 
  if (*s != '[') return 0;
  len = ip_scan(s + 1,ip,sep);
  if (!len) return 0;
  if (s[len + 1] != ']') return 0;
  return len + 2;
}
