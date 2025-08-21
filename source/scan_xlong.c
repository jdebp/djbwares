/* Public domain. */

#include "scan.h"
#include "str.h"

unsigned int scan_xlong_n(register const char *s,register unsigned int max,register unsigned long *u)
{
  register unsigned int pos = 0;
  register unsigned long result = 0;
  register unsigned long c;
  while (pos < max && (c = scan_xdigit(s[pos])) < 16) {
    result = result * 16 + c;
    ++pos;
  }
  *u = result;
  return pos;
}

unsigned int scan_xlong(register const char *s,register unsigned long *u)
{
  return scan_xlong_n(s,str_len(s),u);
}
