#include "readwrite.h"
#include "substdio.h"
#include "subfd.h"

int subfd_read(int fd,char *buf,int len)
{
 if (substdio_flush(subfdout) == -1) return -1;
 return read(fd,buf,len);
}

static char subfd_inbuf[SUBSTDIO_INSIZE];
static struct substdio in =
  SUBSTDIO_FDBUF(subfd_read,0,subfd_inbuf,SUBSTDIO_INSIZE);
struct substdio *subfdin = &in;
