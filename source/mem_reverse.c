/* Public domain. */

#include "mem.h"

void mem_reverse(void *v, register unsigned int len)
{
  unsigned int k;
  register unsigned char *buf = (unsigned char *)v;
  for (k = len / 2;k > 0;) {
    --k;
    register const char c = buf[k];
    buf[k] = buf[len - k - 1];
    buf[len - k - 1] = c;
  }
}
