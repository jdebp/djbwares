#include "substdio.h"
#include "readwrite.h"
#include "exit.h"
#include "auto_home.h"

char buf[16];
substdio out = SUBSTDIO_FDBUF(write,1,buf,sizeof(buf));

int main()
{
 substdio_puts(&out,auto_home);
 substdio_flush(&out);
 _exit(0);
}
