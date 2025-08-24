/* Public domain. */

#include "mem.h"

void mem_copyr(void * vt,register unsigned int n,const void *vf)
{
  register unsigned char * to = (unsigned char *)vt + n;
  register const unsigned char * from = (const unsigned char *)vf + n;
  for (;;) {
    if (!n) return; *--to = *--from; --n;
    if (!n) return; *--to = *--from; --n;
    if (!n) return; *--to = *--from; --n;
    if (!n) return; *--to = *--from; --n;
  }
}
