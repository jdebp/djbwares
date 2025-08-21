#include "scan.h"
#include "uint16.h"
#include "ip.h"
#include "ip6.h"

unsigned int ip6_scan(const char *s,char ip[IP6_LEN],char sep)
{
  unsigned int i;
  unsigned int len;
  unsigned long u;
  char * a;
 
  len = 0;
  a = ip;
  i = scan_xlong(s,&u); if (!i || u > 0xFFFF) return 0; uint16_pack_big(a,u); s += i; len += i; a += 2;
  if (*s != sep) return 0; ++s; ++len;
  i = scan_xlong(s,&u); if (!i || u > 0xFFFF) return 0; uint16_pack_big(a,u); s += i; len += i; a += 2;
  if (*s != sep) return 0; ++s; ++len;
  i = scan_xlong(s,&u); if (!i || u > 0xFFFF) return 0; uint16_pack_big(a,u); s += i; len += i; a += 2;
  if (*s != sep) return 0; ++s; ++len;
  i = scan_xlong(s,&u); if (!i || u > 0xFFFF) return 0; uint16_pack_big(a,u); s += i; len += i; a += 2;
  if (*s != sep) return 0; ++s; ++len;
  i = scan_xlong(s,&u); if (!i || u > 0xFFFF) return 0; uint16_pack_big(a,u); s += i; len += i; a += 2;
  if (*s != sep) return 0; ++s; ++len;
  i = scan_xlong(s,&u); if (!i || u > 0xFFFF) return 0; uint16_pack_big(a,u); s += i; len += i; a += 2;
  if (*s != sep) return 0; ++s; ++len;
  i = scan_xlong(s,&u); if (!i || u > 0xFFFF) return 0; uint16_pack_big(a,u); s += i; len += i; a += 2;
  if (*s != sep) return 0; ++s; ++len;
  i = scan_xlong(s,&u); if (!i || u > 0xFFFF) return 0; uint16_pack_big(a,u); s += i; len += i; a += 2;
  return len;
}
