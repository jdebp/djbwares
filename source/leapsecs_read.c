#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include "tai.h"
#include "leapsecs.h"

struct tai *leapsecs = 0;
int leapsecs_num = 0;

static const char * filenames[4] = {
  "/usr/local/etc/leapsecs.dat",
  "/usr/local/share/libtai/leapsecs.dat",
  "/etc/leapsecs.dat",
  "/usr/share/libtai/leapsecs.dat",
};

int leapsecs_read()
{
  int fd;
  struct stat st;
  struct tai *t;
  int n;
  int i;
  struct tai u;
  const char ** pfn;

  for (pfn = filenames ;; ++pfn) {
    if (pfn >= filenames + sizeof filenames/sizeof *filenames) {
      if (leapsecs) free(leapsecs);
      leapsecs = 0;
      leapsecs_num = 0;
      return 0;
    }
    fd = open(*pfn,O_RDONLY | O_NDELAY);
    if (fd != -1) break;
    if (errno != ENOENT) return -1;
  }

  if (fstat(fd,&st) == -1) { close(fd); return -1; }

  t = (struct tai *) malloc(st.st_size);
  if (!t) { close(fd); return -1; }

  n = read(fd,(char *) t,st.st_size);
  close(fd);
  if (n != st.st_size) { free(t); return -1; }

  n /= sizeof(struct tai);

  for (i = 0;i < n;++i) {
    tai_unpack((char *) &t[i],&u);
    t[i] = u;
  }

  if (leapsecs) free(leapsecs);

  leapsecs = t;
  leapsecs_num = n;
  return 1;
}
