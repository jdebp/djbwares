#include <sys/types.h>
#include <sys/stat.h>
#include "hasdevtcp.h"
#ifdef HASDEVTCP
#include <sys/mkdev.h>
#endif
#include <pwd.h>
#include "strerr.h"
#include "substdio.h"
#include "open.h"
#include "readwrite.h"
#include "exit.h"
#include "auto_home.h"

#define FATAL "configure: fatal: "

void usage(void)
{
  strerr_die1x(100,"configure: usage: configure acct logacct /public hostname hostip ...");
}

char *dir;
char *fn;
char buf[1024];
int fd;
substdio ss;

void fail(void)
{
  strerr_die6sys(111,FATAL,"unable to create ",dir,"/",fn,": ");
}

void makedir(char *s)
{
  fn = s;
  if (mkdir(fn,0700) == -1) fail();
}

void start(char *s)
{
  fn = s;
  fd = open_trunc(fn);
  if (fd == -1) fail();
  substdio_fdbuf(&ss,write,fd,buf,sizeof buf);
}

void outs(const char *s)
{
  if (substdio_puts(&ss,s) == -1) fail();
}

void finish(void)
{
  if (substdio_flush(&ss) == -1) fail();
  if (fsync(fd) == -1) fail();
  close(fd);
}

void perm(int mode)
{
  if (chmod(fn,mode) == -1) fail();
}

char *user;
char *loguser;
struct passwd *pw;

int main(int argc,char **argv)
{
  (void)argc;	/* Silence a compiler warning. */
  umask(022);

  user = argv[1];
  if (!user) usage();
  loguser = argv[2];
  if (!loguser) usage();
  dir = argv[3];
  if (!dir) usage();
  if (dir[0] != '/') usage();

  pw = getpwnam(loguser);
  if (!pw)
    strerr_die3x(111,FATAL,"unknown account ",loguser);

  if (mkdir(dir,0700) == -1)
    strerr_die4sys(111,FATAL,"unable to create ",dir,": ");
  if (chmod(dir,02755) == -1)
    strerr_die4sys(111,FATAL,"unable to set mode of ",dir,": ");
  if (chdir(dir) == -1)
    strerr_die4sys(111,FATAL,"unable to switch to ",dir,": ");

  makedir("httpd");
  perm(03700);
  makedir("httpd/log");
  perm(02755);
  makedir("httpd/log/main");
  if (chown("httpd/log/main",pw->pw_uid,pw->pw_gid) == -1)
    strerr_die4sys(111,FATAL,"unable to set owner of ",dir,"/httpd/log/main: ");
  perm(02755);
  start("httpd/log/status");
  finish();
  if (chown("httpd/log/status",pw->pw_uid,pw->pw_gid) == -1)
    strerr_die4sys(111,FATAL,"unable to set owner of ",dir,"/httpd/log/status: ");
  perm(0644);

  start("httpd/run");
  outs("#!/bin/sh\nexec 2>&1\nexec");
  outs(" envuidgid "); outs(user);
  outs(" softlimit -o20 -d50000");
  outs(" tcpserver -vDRH -l0 -b50 -c100 0 80 "); /*-l needs to be separate*/
  outs(auto_home); outs("/bin/httpd "); outs(dir); outs("/file\n");
  finish();
  perm(0755);

  start("httpd/log/run");
  outs("#!/bin/sh\nexec");
  outs(" setuidgid "); outs(loguser);
  outs(" multilog t ./main '-*' '+* * status: *' =status\n");
  finish();
  perm(0755);

  makedir("ftpd");
  perm(03700);
  makedir("ftpd/log");
  perm(02755);
  makedir("ftpd/log/main");
  if (chown("ftpd/log/main",pw->pw_uid,pw->pw_gid) == -1)
    strerr_die4sys(111,FATAL,"unable to set owner of ",dir,"/ftpd/log/main: ");
  perm(02755);
  start("ftpd/log/status");
  finish();
  if (chown("ftpd/log/status",pw->pw_uid,pw->pw_gid) == -1)
    strerr_die4sys(111,FATAL,"unable to set owner of ",dir,"/ftpd/log/status: ");
  perm(0644);

  start("ftpd/run");
  outs("#!/bin/sh\nexec 2>&1\nexec");
  outs(" envuidgid "); outs(user);
  outs(" softlimit -o20 -d50000");
  outs(" tcpserver -vDRH -l0 -b20 -c40 -B'220 Features: a p .\r\n' 0 21 "); /*-l needs to be separate*/
  outs(auto_home); outs("/bin/ftpd "); outs(dir); outs("/file\n");
  finish();
  perm(0755);

  start("ftpd/log/run");
  outs("#!/bin/sh\nexec");
  outs(" setuidgid "); outs(loguser);
  outs(" multilog t ./main '-*' '+* * status: *' =status\n");
  finish();
  perm(0755);

  makedir("file");
  perm(02755);
  makedir("file/0");
  perm(02755);

#ifdef HASDEVTCP
  makedir("file/etc");
  perm(02755);
  makedir("file/dev");
  perm(02755);
  start("file/etc/netconfig");
  outs("tcp tpi_cots_ord v inet tcp /dev/tcp -\n");
  finish();
  perm(0645);
  umask(000);
  if (mknod("file/dev/tcp",S_IFCHR | 0667,makedev(11,42)) == -1)
    strerr_die4sys(111,FATAL,"unable to create device ",dir,"/file/dev/tcp: ");
  umask(022);
#endif

  if (chdir("file") == -1)
    strerr_die4sys(111,FATAL,"unable to switch to ",dir,"/file: ");
  for (argv += 4;*argv;++argv)
    if (symlink("0",*argv) == -1)
      strerr_die6sys(111,FATAL,"unable to create ",dir,"/file/",*argv,": ");

  _exit(0);
}
