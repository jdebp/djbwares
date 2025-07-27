#include <sys/ioctl.h>
#include <termios.h>

int main(void)
{
  ioctl(1,TIOCNXCL,(char *) 0);
}
