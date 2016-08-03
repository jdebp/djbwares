#include "env.h"
#include "exit.h"
#include "scan.h"
#include "prot.h"
#include <unistd.h>

extern void doit(void);

int main(int argc,char **argv)
{
  (void)argc;	/* Silence a compiler warning. */
  char *x;
  unsigned long id;

  x = argv[1];
  if (x) {
    if (chdir(x) == -1) _exit(20);
    if (chroot(".") == -1) _exit(30);
  }

  x = env_get("GID");
  if (x) {
    scan_ulong(x,&id);
    if (prot_gid((int) id) == -1) _exit(30);
  }

  x = env_get("UID");
  if (x) {
    scan_ulong(x,&id);
    if (prot_uid((int) id) == -1) _exit(30);
  }

  doit();
}
