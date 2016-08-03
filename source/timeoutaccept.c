#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "timeoutaccept.h"
#include "ndelay.h"
#include "select.h"
#include "error.h"
#include "readwrite.h"

int timeoutaccept(int s,int timeout)
{
  struct sockaddr_in sa;
  int dummy;
  int fd;
  fd_set rfds;
  struct timeval tv;

  if (ndelay_on(s) == -1) return -1;

  FD_ZERO(&rfds);
  FD_SET(s,&rfds);
  tv.tv_sec = timeout; tv.tv_usec = 0;

  if (select(s + 1,&rfds,(fd_set *) 0,(fd_set *) 0,&tv) == -1) return -1;

  dummy = sizeof sa;
  fd = accept(s,(struct sockaddr *) &sa,&dummy);
  if (fd == -1) return -1;

  ndelay_off(s);
  return fd;
}
