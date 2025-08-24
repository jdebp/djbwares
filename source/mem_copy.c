/* Public domain. */

#include "mem.h"

void mem_copy(void *vt, register unsigned int n, const void *vf)
{
  register unsigned char * to = (unsigned char *)vt;
  register const unsigned char * from = (const unsigned char *)vf;
  for (;;) {
    if (!n) return; *to++ = *from++; --n;
    if (!n) return; *to++ = *from++; --n;
    if (!n) return; *to++ = *from++; --n;
    if (!n) return; *to++ = *from++; --n;
  }
}
