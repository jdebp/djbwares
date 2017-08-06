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
#include "ucspi.h"

static void log(const char *fn,const char *result1,const char *result2,int cmd)
{
  int i;
  char ch;
  const char *x;

  x = ucspi_get_remoteip_str("0", "0", "0");
  substdio_puts(subfderr,x);
  substdio_puts(subfderr,cmd > 2 ? " dir ": cmd > 1 ? " ls ": cmd > 0 ? " cd ": " read ");

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

int file_open(const char *fn,struct tai *mtime,unsigned long *length,int flagreg,int flagdir,int cmd)
{
  struct stat st;
  int fd;

  fd = (flagdir ? open_readdir : open_read)(fn);
  if (fd == -1) {
    log(fn,": open failed: ",error_str(errno),cmd);
    if (error_temp(errno)) _exit(23);
    return -1;
  }
  if (fstat(fd,&st) == -1) {
    log(fn,": fstat failed: ",error_str(errno),cmd);
    close(fd);
    if (error_temp(errno)) _exit(23);
    return -1;
  }
  if ((st.st_mode & 0444) != 0444) {
    log(fn,": ","not ugo+r",cmd);
    close(fd);
    errno = error_acces;
    return -1;
  }
  if ((st.st_mode & 0101) == 0001) {
    log(fn,": ","o+x but u-x",cmd);
    close(fd);
    errno = error_acces;
    return -1;
  }
  if (flagreg)
    if ((st.st_mode & S_IFMT) != S_IFREG) {
      log(fn,": ","not a regular file",cmd);
      close(fd);
      errno = error_acces;
      return -1;
    }
  if (flagdir)
    if ((st.st_mode & S_IFMT) != S_IFDIR) {
      log(fn,": ","not a directory",cmd);
      close(fd);
      errno = error_acces;
      return -1;
    }

  log(fn,": ","success",cmd);

  *length = st.st_size;
  tai_unix(mtime,st.st_mtime);

  return fd;
}
