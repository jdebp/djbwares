#include "pathdecode.h"
#include "file.h"
#include "filetype.h"
#include "percent.h"
#include "stralloc.h"
#include "sig.h"
#include "exit.h"
#include "fmt.h"
#include "case.h"
#include "str.h"
#include "tai.h"
#include "timeoutread.h"
#include "timeoutwrite.h"
#include "buffer.h"
#include "error.h"
#include "getln.h"
#include "byte.h"
#include "ucspi.h"
#include "subfd.h"
#include "env.h"
#include <unistd.h>
#include <sys/socket.h>

int safewrite(int fd,const char *buf,int len)
{
  int r;
  r = timeoutwrite(60,fd,buf,len);
  if (r <= 0) _exit(0);
  return r;
}

static char outbuf[BUFFER_OUTSIZE];
static buffer out = BUFFER_INIT(safewrite,1,outbuf,sizeof outbuf);

void out_put(const char *s,int len)
{
  buffer_put(&out,s,len);
}

void out_puts(const char *s)
{
  buffer_puts(&out,s);
}

void out_flush(void)
{
  buffer_flush(&out);
}

static void log(const char *code,const char *msg)
{
  const char *x;

  x = ucspi_get_remoteip_str("0", "0", "0");
  substdio_puts(subfderr,x);
  substdio_puts(subfderr," barf ");
  substdio_puts(subfderr,code);
  substdio_puts(subfderr,msg);
  substdio_puts(subfderr,"\n");
  substdio_flush(subfderr);
}

static stralloc url = stralloc_static_0;
static stralloc host = stralloc_static_0;
static stralloc path = stralloc_static_0;
static int flaglogunsupported = 0;

static char filebuf[1024];

void header(const char *code,const char *message)
{
  out_puts(code);
  out_puts(message);
  out_puts("\r\n");
}

void barf(const char *code,const char *message)
{
  if (flaglogunsupported)
    log(code, message);
  header(code,message);
  out_flush();
  _exit(0);
}

static stralloc fn = stralloc_static_0;
static stralloc contenttype = stralloc_static_0;

void get(void)
{
  unsigned long length;
  int fd;
  int r;
  struct tai mtime;

  if (!host.len)
    barf("59 ","GEMINI requests must include a host name.");
  if (!path.len || (path.s[path.len - 1] == '/')) {
    if (!stralloc_cats(&path,"index.gemini")) _exit(21);
    if (!stralloc_copys(&url,"gemini://")) _exit(21);
    if (!stralloc_cat(&url,&host)) _exit(21);
    if (!stralloc_cat(&url,&path)) _exit(21);
    if (!stralloc_0(&url)) _exit(21);
    barf("30 ",url.s);
  }

  case_lowerb(host.s,host.len);
  percent(&path);

  if (!stralloc_copys(&fn,"./")) _exit(21);
  if (!stralloc_cat(&fn,&host)) _exit(21);
  if (!stralloc_cats(&fn,"/")) _exit(21);
  if (!stralloc_cat(&fn,&path)) _exit(21);
  pathdecode(&fn);
  if (!stralloc_0(&fn)) _exit(21);

  fd = file_open(fn.s,&mtime,&length,1,0,0);
  if (fd == -1)
    barf("51 ",error_str(errno));

  filetype(fn.s,&contenttype);
  if (!stralloc_0(&contenttype)) _exit(21);
  header("20 ",contenttype.s);

  for (;;) {
    r = read(fd,filebuf,sizeof filebuf);
    if (r == -1) _exit(23);
    if (r == 0) break;
    out_put(filebuf,r);
  }
  out_flush();
  close(fd);
}

static stralloc line = stralloc_static_0;

int saferead(int fd,char *buf,int len)
{
  int r;
  out_flush();
  r = timeoutread(60,fd,buf,len);
  if (r <= 0) _exit(0);
  return r;
}

static char inbuf[BUFFER_INSIZE];
static buffer in = BUFFER_INIT(saferead,0,inbuf,sizeof inbuf);

void readline(void)
{
  int match;

  if (getln(&in,&line,&match,'\n') == -1) _exit(21);
  if (!match) _exit(0);
  if (line.len && (line.s[line.len - 1] == '\n')) --line.len;
  if (line.len && (line.s[line.len - 1] == '\r')) --line.len;
}

void doit()
{
  unsigned int i;

  if (env_get("LOGUNSUPPORTED"))
    flaglogunsupported = 1;

  sig_ignore(sig_pipe);

  readline();

  if (!line.len) return;

  // This is a MUST in the specification, even though we don't have a limit other than memory.
  if (line.len >= 1024)
    barf("59 ","GEMINI requests must be less than 1024 characters.");

  if (!stralloc_copys(&host,"")) _exit(21);
  if (!stralloc_copys(&path,"")) _exit(21);

  if (case_startb(line.s,line.len,"gemini://")) {
    if (!stralloc_copyb(&host,line.s + 9,line.len - 9)) _exit(21);
    i = byte_chr(host.s,host.len,'/');
    if (!stralloc_copyb(&path,host.s + i,host.len - i)) _exit(21);
    host.len = i;
  }
  else if (case_startb(line.s,line.len,"//")) {
    if (!stralloc_copyb(&host,line.s + 2,line.len - 2)) _exit(21);
    i = byte_chr(host.s,host.len,'/');
    if (!stralloc_copyb(&path,host.s + i,host.len - i)) _exit(21);
    host.len = i;
  }
  else
    if (!stralloc_copy(&path,&line)) _exit(21);

  // This is a MUST in the specification.
  i = byte_chr(host.s,host.len,'@');
  if (i != host.len)
    barf("59 ","GEMINI requests may not have a user part.");
  // This is a MUST in the specification.
  if (!path.len)
    if (!stralloc_cats(&path,"/")) _exit(21);
  // This is a MUST in the specification.
  i = byte_chr(path.s,path.len,'#');
  if (i != path.len)
    barf("59 ","GEMINI requests may not have a fragment part.");

  // Just strip the port.
  i = byte_chr(host.s,host.len,':');
  host.len = i;

  get();
  _exit(0);
}
