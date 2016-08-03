#include <sys/file.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include "ttyctrl.h"

int ttyctrl()
{
  int fd;

  fd = dup(3);
  if (fd != -1) { if (tcgetpgrp(fd) != -1) return fd; close(fd); }
  fd = open("/dev/tty",O_RDWR);
  if (fd != -1) { if (tcgetpgrp(fd) != -1) return fd; close(fd); }
  fd = dup(2);
  if (fd != -1) { if (tcgetpgrp(fd) != -1) return fd; close(fd); }
  fd = dup(0);
  if (fd != -1) { if (tcgetpgrp(fd) != -1) return fd; close(fd); }
  fd = dup(1);
  if (fd != -1) { if (tcgetpgrp(fd) != -1) return fd; close(fd); }
  return -1;
}
