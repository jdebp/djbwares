/* Public domain. */

#include "scan.h"

unsigned int scan_xlong(register const char *s,register unsigned long *u)
{
  register unsigned int pos = 0;
  register unsigned long result = 0;
  register unsigned long c;
  while ((c = scan_xdigit(s[pos])) < 16) {
    result = result * 16 + c;
    ++pos;
  }
  *u = result;
  return pos;
}
