#include "fmt.h"
#include "uint16.h"
#include "ip6.h"

unsigned int ip6_fmt(char *s,const char ip[16],char sep)
{
  unsigned int len;
  unsigned int i;
  uint16 u;
  const char * a;
 
  len = 0;
  a = ip;
  uint16_unpack_big(a,&u); i = fmt_xlong(s,u); len += i; a += 2; if (s) s += i;
  if (s) *s++ = sep; ++len;
  uint16_unpack_big(a,&u); i = fmt_xlong(s,u); len += i; a += 2; if (s) s += i;
  if (s) *s++ = sep; ++len;
  uint16_unpack_big(a,&u); i = fmt_xlong(s,u); len += i; a += 2; if (s) s += i;
  if (s) *s++ = sep; ++len;
  uint16_unpack_big(a,&u); i = fmt_xlong(s,u); len += i; a += 2; if (s) s += i;
  if (s) *s++ = sep; ++len;
  uint16_unpack_big(a,&u); i = fmt_xlong(s,u); len += i; a += 2; if (s) s += i;
  if (s) *s++ = sep; ++len;
  uint16_unpack_big(a,&u); i = fmt_xlong(s,u); len += i; a += 2; if (s) s += i;
  if (s) *s++ = sep; ++len;
  uint16_unpack_big(a,&u); i = fmt_xlong(s,u); len += i; a += 2; if (s) s += i;
  if (s) *s++ = sep; ++len;
  uint16_unpack_big(a,&u); i = fmt_xlong(s,u); len += i; a += 2; if (s) s += i;
  return len;
}
