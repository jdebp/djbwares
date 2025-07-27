#include <sys/types.h>
#include <sys/time.h>

int main()
{
  hrtime_t t;

  t = gethrtime();
}
