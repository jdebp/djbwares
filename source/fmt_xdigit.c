#include "fmt.h"

char fmt_xdigit(unsigned char u)
{
  char c;

  c = '0' + (u & 15); 
  if (c > '0' + 9) c += 'a' - '0' - 10;
  return c;
}
