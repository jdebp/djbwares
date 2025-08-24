/* Public domain. */

#include "mem.h"

int mem_diff(const void *vs,register unsigned int n,const void *vt)
{
  register const unsigned char * s = (const unsigned char *)vs;
  register const unsigned char * t = (const unsigned char *)vt;
  for (;;) {
    if (!n) return 0; if (*s != *t) break; ++s; ++t; --n;
    if (!n) return 0; if (*s != *t) break; ++s; ++t; --n;
    if (!n) return 0; if (*s != *t) break; ++s; ++t; --n;
    if (!n) return 0; if (*s != *t) break; ++s; ++t; --n;
  }
  return ((int)(unsigned int)*s)
       - ((int)(unsigned int)*t);
}
