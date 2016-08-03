#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <fcntl.h>

void main()
{
  struct stat st;
  int fd;

  if (stat("/dev/ptmx",&st) == -1) exit(1);
  exit(0);

  fd = posix_openpt(O_RDWR|O_NOCTTY);
  grantpt(fd);
  unlockpt(fd);
}
