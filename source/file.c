#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "subfd.h"
#include "error.h"
#include "file.h"
#include "byte.h"
#include "str.h"
#include "tai.h"
#include "env.h"
#include "open.h"

static void log(char *fn,char *result1,char *result2,int flagread)
{
  int i;
  char ch;
  char *x;

  x = env_get("TCPREMOTEIP");
  if (!x) x = "0";
  substdio_puts(subfderr,x);
  substdio_puts(subfderr,flagread ? " read ": " dir ");

  for (i = 0;i < 100;++i) {
    ch = fn[i];
    if (!ch) break;
    if (ch < 32) ch = '?';
    if (ch > 126) ch = '?';
    if (ch == ' ') ch = '_';
    substdio_put(subfderr,&ch,1);
  }
  if (i == 100)
    substdio_puts(subfderr,"...");

  substdio_puts(subfderr,result1);
  substdio_puts(subfderr,result2);
  substdio_puts(subfderr,"\n");
  substdio_flush(subfderr);
}

int file_open(char *fn,struct tai *mtime,unsigned long *length,int flagread)
{
  struct stat st;
  int fd;

  fd = open_read(fn);
  if (fd == -1) {
    log(fn,": open failed: ",error_str(errno),flagread);
    if (error_temp(errno)) _exit(23);
    return -1;
  }
  if (fstat(fd,&st) == -1) {
    log(fn,": fstat failed: ",error_str(errno),flagread);
    close(fd);
    if (error_temp(errno)) _exit(23);
    return -1;
  }
  if ((st.st_mode & 0444) != 0444) {
    log(fn,": ","not ugo+r",flagread);
    close(fd);
    errno = error_acces;
    return -1;
  }
  if ((st.st_mode & 0101) == 0001) {
    log(fn,": ","o+x but u-x",flagread);
    close(fd);
    errno = error_acces;
    return -1;
  }
  if (flagread)
    if ((st.st_mode & S_IFMT) != S_IFREG) {
      log(fn,": ","not a regular file",flagread);
      close(fd);
      errno = error_acces;
      return -1;
    }

  log(fn,": ","success",flagread);

  *length = st.st_size;
  tai_unix(mtime,st.st_mtime);

  return fd;
}
