#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include <time.h>
#include "substdio.h"
#include "timeoutwrite.h"
#include "error.h"
#include "exit.h"
#include "direntry.h"
#include "fmt.h"
#include "open.h"
#include "fetch.h"

int fetch_ascii = 1;
unsigned long fetch_rest = 0;

static char inbuf[1024];
static char ssbuf[1024];
static substdio ss;
static int trouble;

static time_t now;
static struct stat st;
static char strnum[FMT_ULONG];

extern void out_puts(const char *s);

static int datawrite(int fd,char *buf,int len)
{
  int w;

  if (trouble) return -1;

  if (fetch_rest) {
    if (len > fetch_rest) len = fetch_rest;
    fetch_rest -= len;
    return len;
  }

  w = timeoutwrite(60,fd,buf,len);
  if (w == -1) if (errno != error_intr) trouble = errno;
  return w;
}

static void printstat(const struct stat * st)
{
  substdio_puts(&ss,"+i");
  substdio_put(&ss,strnum,fmt_ulong(strnum,(unsigned long) st->st_dev));
  substdio_puts(&ss,".");
  substdio_put(&ss,strnum,fmt_ulong(strnum,(unsigned long) st->st_ino));

  if (st->st_mtime > 0)
    if (st->st_mtime < now - 60) {
      substdio_puts(&ss,",m");
      substdio_put(&ss,strnum,fmt_ulong(strnum,(unsigned long) st->st_mtime));
    }

  if ((st->st_mode & S_IFMT) == S_IFDIR)
    substdio_puts(&ss,",/");
  if (((st->st_mode & S_IFMT) == S_IFREG) && ((st->st_mode & 0444) == 0444)) {
    substdio_puts(&ss,",r,s");
    substdio_put(&ss,strnum,fmt_ulong(strnum,(unsigned long) st->st_size));
  }
  substdio_puts(&ss,",\t");
}

static void list(char *fn,int flaglong)
{
  int i;

  if (fn[0] == '.') return;
  for (i = 0;fn[i];++i) {
    if ((fn[i] >= 0) && (fn[i] <= 32)) return;
    if (fn[i] == '~') return;
  }

  if (flaglong) {
    if (stat(fn,&st) == -1) {
      if (error_temp(errno)) _exit(23);
      return;
    }
    printstat(&st);
  }

  substdio_puts(&ss,fn);
  substdio_puts(&ss,"\r\n");
}

static void doit(char *fn,int fddata,int fdfile,int how)
{
  DIR *dir;
  direntry *d;
  int r;
  int i;

  substdio_fdbuf(&ss,datawrite,fddata,ssbuf,sizeof ssbuf);

  switch(how) {
    case FETCH_LISTONE:
      if (fstat(fdfile,&st) == -1) break;
      printstat(&st);
      for (i = 0;fn[i];++i)
	if (fn[i] == '\n')
	  substdio_put(&ss,"",1);
	else
	  substdio_put(&ss,&fn[i],1);
      substdio_puts(&ss,"\r\n");
      break;

    case FETCH_LIST:
    case FETCH_NLST:
      if (fchdir(fdfile) == -1) {
	trouble = errno;
	return;
      }

      dir = opendir(".");
      if (!dir) _exit(23); /* XXX: could be out of memory */
      while ((d = readdir(dir))) /* XXX: temporary errors */
	list(d->d_name,how == FETCH_LIST);
      closedir(dir);

      break;

    default:
      for (;;) {
	r = read(fdfile,inbuf,sizeof inbuf);
	if (r == -1) {
	  if (errno == error_intr) continue;
	  _exit(23);
	}
	if (r == 0)
	  break;
	if (!fetch_ascii)
	  substdio_put(&ss,inbuf,r);
	else
	  for (i = 0;i < r;++i) {
	    if (inbuf[i] == '\n')
	      substdio_put(&ss,"\r",1);
	    substdio_put(&ss,inbuf + i,1);
	  }
      }
      break;
  }

  substdio_flush(&ss);
}

void fetch(char *fn,int fddata,int fdfile,int how)
{
  int fdcurrent;

  time(&now);

  fdcurrent = open_read(".");
  if (fdcurrent == -1) _exit(23);

  trouble = 0;
  doit(fn,fddata,fdfile,how);
  close(fddata);
  close(fdfile);

  if (!trouble)
    out_puts("226 Success.\r\n");
  else {
    out_puts("426 Transmission failure: ");
    out_puts(error_str(trouble));
    out_puts("\r\n");
  }

  if (fchdir(fdcurrent) == -1) _exit(23);
  close(fdcurrent);

  fetch_rest = 0;
}
