#include "conf.h"
#include <unistd.h>
#include <errno.h>
#include <limits.h>

unsigned int conf_path_max(void)
{
  long m;

  errno = 0;
  m = pathconf(".", _PC_PATH_MAX);
  if (0 > m) {
#if defined(PATH_MAX)
    return PATH_MAX;
#elif defined(_XOPEN_PATH_MAX)
    return _XOPEN_PATH_MAX;
#endif
    return _POSIX_PATH_MAX;
  }
  if (UINT_MAX < m) return UINT_MAX;
  return (unsigned int)m;
}
