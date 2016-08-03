#include "env_write.h"
#include "strerr.h"
#include <unistd.h>

int main(int argc,char ** argv)
{
  (void)argc;	/* Silence a compiler warning. */
  if (setsid() == -1)
    strerr_warn1("ttydetach: warning: unable to setsid",0);
  if (!env_unset("TTY"))
    strerr_die2x(111,"ttydetach: fatal: ","out of memory");
  execvp(argv[1],argv + 1);
  strerr_die4sys(111,"ttydetach: fatal: ","unable to run ",argv[1],": ");
}
