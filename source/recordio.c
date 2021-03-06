#include "sig.h"
#include "buffer.h"
#include "strerr.h"
#include "str.h"
#include "byte.h"
#include "readwrite.h"
#include "exit.h"
#include "fmt.h"
#include "iopause.h"
#include "pathexec.h"
#include "fd.h"

#define FATAL "recordio: fatal: "

char pid[FMT_ULONG];

char recordbuf[512];
buffer ssrecord = BUFFER_INIT(buffer_unixwrite,2,recordbuf,sizeof recordbuf);

void record(char *buf,int len,char *direction) /* 1 <= len <= 256 */
{
  int i;

  while (len) {
    buffer_puts(&ssrecord,pid);
    buffer_puts(&ssrecord,direction);

    i = byte_chr(buf,len,'\n');
    buffer_put(&ssrecord,buf,i);

    if (i == len) {
      buffer_puts(&ssrecord,"+\n");
      buffer_flush(&ssrecord);
      return;
    }

    buffer_puts(&ssrecord," \n");
    buffer_flush(&ssrecord);
    buf += i + 1;
    len -= i + 1;
  }
}

int leftstatus = 0;
char leftbuf[256];
int leftlen;
int leftpos;

int rightstatus = 0;
char rightbuf[256];
int rightlen;
int rightpos;

void doit(int fdleft,int fdright) /* copy 0 -> fdleft, copy fdright -> 1 */
{
  struct taia stamp;
  struct taia deadline;
  iopause_fd x[4];
  int xlen;
  iopause_fd *io0;
  iopause_fd *ioleft;
  iopause_fd *io1;
  iopause_fd *ioright;
  int r;

  for (;;) {
    xlen = 0;

    io0 = 0;
    if (leftstatus == 0) {
      io0 = &x[xlen++];
      io0->fd = 0;
      io0->events = IOPAUSE_READ;
    }
    ioleft = 0;
    if (leftstatus == 1) {
      ioleft = &x[xlen++];
      ioleft->fd = fdleft;
      ioleft->events = IOPAUSE_WRITE;
    }

    ioright = 0;
    if (rightstatus == 0) {
      ioright = &x[xlen++];
      ioright->fd = fdright;
      ioright->events = IOPAUSE_READ;
    }
    io1 = 0;
    if (rightstatus == 1) {
      io1 = &x[xlen++];
      io1->fd = 1;
      io1->events = IOPAUSE_WRITE;
    }

    taia_now(&stamp);
    taia_uint(&deadline,3600);
    taia_add(&deadline,&stamp,&deadline);
    iopause(x,xlen,&deadline,&stamp);

    if (io0 && io0->revents) {
      r = read(0,leftbuf,sizeof leftbuf);
      if (r <= 0) {
        leftstatus = -1;
        close(fdleft);
        buffer_puts(&ssrecord,pid);
        buffer_puts(&ssrecord," < [EOF]\n");
        buffer_flush(&ssrecord);
      }
      else {
        leftstatus = 1; leftpos = 0; leftlen = r;
        record(leftbuf,r," < ");
      }
    }

    if (ioleft && ioleft->revents) {
      r = write(fdleft,leftbuf + leftpos,leftlen - leftpos);
      if (r == -1) break;
      leftpos += r;
      if (leftpos == leftlen) leftstatus = 0;
    }

    if (ioright && ioright->revents) {
      r = read(fdright,rightbuf,sizeof rightbuf);
      if (r <= 0) {
        buffer_puts(&ssrecord,pid);
        buffer_puts(&ssrecord," > [EOF]\n");
        buffer_flush(&ssrecord);
        break;
      }
      rightstatus = 1; rightpos = 0; rightlen = r;
      record(rightbuf,r," > ");
    }

    if (io1 && io1->revents) {
      r = write(1,rightbuf + rightpos,rightlen - rightpos);
      if (r == -1) break;
      rightpos += r;
      if (rightpos == rightlen) rightstatus = 0;
    }
  }

  _exit(0);
}

int main(int argc,char **argv,char **envp)
{
  int piin[2];
  int piout[2];

  pid[fmt_ulong(pid,getpid())] = 0;

  if (argc < 2)
    strerr_die1x(100,"recordio: usage: recordio program [ arg ... ]");

  if (pipe(piin) == -1)
    strerr_die2sys(111,FATAL,"unable to create pipe: ");
  if (pipe(piout) == -1)
    strerr_die2sys(111,FATAL,"unable to create pipe: ");

  switch(fork()) {
    case -1:
      strerr_die2sys(111,FATAL,"unable to fork: ");
    case 0:
      sig_ignore(sig_pipe);
      close(piin[0]);
      close(piout[1]);
      doit(piin[1],piout[0]);
  }

  close(piin[1]);
  close(piout[0]);
  if (fd_move(0,piin[0]) == -1)
    strerr_die2sys(111,FATAL,"unable to move descriptors: ");
  if (fd_move(1,piout[1]) == -1)
    strerr_die2sys(111,FATAL,"unable to move descriptors: ");

  pathexec_run(argv[1],argv + 1,envp);
  strerr_die4sys(111,FATAL,"unable to run ",argv[1],": ");
}
