#include "substdio.h"
#include "readwrite.h"
#include "exit.h"
#include "auto_home.h"

static char buf[16];
static substdio out = SUBSTDIO_FDBUF(write,1,buf,sizeof(buf));

int main(void)
{
 substdio_puts(&out,auto_home);
 substdio_flush(&out);
 _exit(0);
}
