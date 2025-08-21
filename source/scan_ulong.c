/* Public domain. */

#include "scan.h"
#include "str.h"

unsigned int scan_ulong_n(register const char *s,register unsigned int max,register unsigned long *u)
{
  register unsigned int pos = 0;
  register unsigned long result = 0;
  register unsigned long c;
  while (pos < max && (c = (unsigned long) (unsigned char) (s[pos] - '0')) < 10) {
    /* It is unclear whether this is intentional; but there's no checking for overflow here. */
    result = result * 10 + c;
    ++pos;
  }
  *u = result;
  return pos;
}

unsigned int scan_ulong(const char *s,unsigned long *u)
{
  return scan_ulong_n(s,str_len(s),u);
}
