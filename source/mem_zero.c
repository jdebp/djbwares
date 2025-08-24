#include "mem.h"

void mem_zero(void * v,register unsigned int n)
{
  register unsigned char *s = (unsigned char *)v;
  for (;;) {
    if (!n) break; *s++ = 0; --n;
    if (!n) break; *s++ = 0; --n;
    if (!n) break; *s++ = 0; --n;
    if (!n) break; *s++ = 0; --n;
  }
}
