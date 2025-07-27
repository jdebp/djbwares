#include <sys/ioctl.h>
#include <termios.h>

int main(void)
{
  ioctl(1,TIOCEXCL,(char *) 0);
}
