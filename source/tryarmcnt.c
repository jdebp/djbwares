#include <sys/types.h>
#include "exit.h"
int main()
{
  u_int64_t x, y;

  x = y = 0;
  asm volatile("mrs %0, cntvct_el0" : "=r"(x));
  asm volatile("mrs %0, cntvct_el0" : "=r"(y));

  if (x != y) _exit(0);
  _exit(1);
}
