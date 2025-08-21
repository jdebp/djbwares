#include "fmt.h"
#include "uint16.h"
#include "ip.h"
#include "ip6.h"

unsigned int ip6_fmt(char *s,const char ip[IP6_LEN],char sep)
{
  unsigned int len;
  unsigned int i;
  uint16 u;
  const char * a;
 
  len = 0;
  a = ip;
  uint16_unpack_big(a,&u); i = fmt_xlong(s,u); len += i; a += 2; if (s) s += i;
  ++len; if (s) *s++ = sep;
  uint16_unpack_big(a,&u); i = fmt_xlong(s,u); len += i; a += 2; if (s) s += i;
  ++len; if (s) *s++ = sep;
  uint16_unpack_big(a,&u); i = fmt_xlong(s,u); len += i; a += 2; if (s) s += i;
  ++len; if (s) *s++ = sep;
  uint16_unpack_big(a,&u); i = fmt_xlong(s,u); len += i; a += 2; if (s) s += i;
  ++len; if (s) *s++ = sep;
  uint16_unpack_big(a,&u); i = fmt_xlong(s,u); len += i; a += 2; if (s) s += i;
  ++len; if (s) *s++ = sep;
  uint16_unpack_big(a,&u); i = fmt_xlong(s,u); len += i; a += 2; if (s) s += i;
  ++len; if (s) *s++ = sep;
  uint16_unpack_big(a,&u); i = fmt_xlong(s,u); len += i; a += 2; if (s) s += i;
  ++len; if (s) *s++ = sep;
  uint16_unpack_big(a,&u); i = fmt_xlong(s,u); len += i; a += 2; if (s) s += i;
  return len;
}
