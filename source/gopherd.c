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
#include "caltime.h"
#include "timeoutread.h"
#include "timeoutwrite.h"
#include "buffer.h"
#include "error.h"
#include "getln.h"
#include "byte.h"
#include "ucspi.h"
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

int readline2(buffer * b, stralloc * s)
{
  int match;

  if (getln(b,s,&match,'\n') == -1) _exit(21);
  if (!match) return 0;
  if (s->len && (s->s[s->len - 1] == '\n')) --s->len;
  if (s->len && (s->s[s->len - 1] == '\r')) --s->len;
  return 1;
}

static char strnum[FMT_ULONG];

static int level = 0;
static int protocol = 0;
static int flagmenu = 0;
static stralloc path = stralloc_static_0;
static stralloc plus = stralloc_static_0;
static stralloc rqdf = stralloc_static_0;
static stralloc file = stralloc_static_0;

static char filebuf[1024];

void barf(unsigned code, const char * selector, const char *message)
{
  if (protocol > 0) {
    out_puts("-""-2\r\n");
    out_put(strnum,fmt_ulong(strnum,code));
    out_puts(" ");
  } else
    out_puts("3");
  out_puts(message);
  if (protocol < 1) {
    out_puts("\t");
    out_puts(selector);
    out_puts("\t.\t.\t+\r\n");
  }
  out_flush();
  if (protocol > 0) {
    shutdown(1,1);
    sleep(1); /* XXX */
  }
  _exit(0);
}

int gopherdate(stralloc *sa,const struct tai *t)
{
  struct caltime ct;

  caltime_utc(&ct,t,(int *) 0,(int *) 0);

  if (!stralloc_copys(sa,"<")) return 0;
  if (!stralloc_catuint0(sa,ct.date.year,4)) return 0;
  if (!stralloc_catuint0(sa,ct.date.month,2)) return 0;
  if (!stralloc_catuint0(sa,ct.date.day,2)) return 0;
  if (!stralloc_catuint0(sa,ct.hour,2)) return 0;
  if (!stralloc_catuint0(sa,ct.minute,2)) return 0;
  if (!stralloc_catuint0(sa,ct.second,2)) return 0;
  if (!stralloc_cats(sa,">")) return 0;

  return 1;
}

static stralloc nowstr = stralloc_static_0;
static stralloc mtimestr = stralloc_static_0;
static stralloc contenttype = stralloc_static_0;

void headers(stralloc * s, const struct tai * mtime, unsigned long length, const char * name)
{
  struct tai now;

  tai_now(&now);
  if (!gopherdate(&nowstr,&now)) _exit(21);
  if (!gopherdate(&mtimestr,mtime)) _exit(21);
  filetype(name,&contenttype);

  if (!stralloc_cats(s," Server: publicfile\r\n Admin: This is a secure server <postmaster@localhost>\r\n Date: ")) _exit(21);
  if (!stralloc_catb(s,nowstr.s,nowstr.len)) _exit(21);
  if (!stralloc_cats(s,"\r\n Mod-Date: ")) _exit(21);
  if (!stralloc_catb(s,mtimestr.s,mtimestr.len)) _exit(21);
  if (!stralloc_cats(s,"\r\n Content-Length: ")) _exit(21);
  if (!stralloc_catb(s,strnum,fmt_ulong(strnum,length))) _exit(21);
  if (!stralloc_cats(s,"\r\n ")) _exit(21);
  if (!stralloc_catb(s,contenttype.s,contenttype.len)) _exit(21);
}

static stralloc fn = stralloc_static_0;
static stralloc attr = stralloc_static_0;
static stralloc record = stralloc_static_0;
static stralloc name_field = stralloc_static_0;
static stralloc path_field = stralloc_static_0;
static stralloc host_field = stralloc_static_0;
static stralloc port_field = stralloc_static_0;
static const char * localhost = 0;
static const char * localport = 0;

void get(void)
{
  unsigned long length;
  struct tai mtime;
  int fd;
  int r;

  percent(&file);

  if (!stralloc_copys(&fn,"./")) _exit(21);
  if (!stralloc_cats(&fn,localhost)) _exit(21);
  if (!file.len || '/' != file.s[0]) {
    if (!stralloc_append(&fn,"/")) _exit(21);
  }
  if (!stralloc_cat(&fn,&file)) _exit(21);
  pathdecode(&fn);
  if (!stralloc_0(&fn)) _exit(21);

  fd = file_open(fn.s,&mtime,&length,1,0,0);
  if (fd == -1)
    barf(1, fn.s, error_str(errno));

  if (0 == level) {
    /* At level 0, just send the file data. */
    if (protocol > 0) {
      out_puts("+");
      out_put(strnum,fmt_ulong(strnum,length));
      out_puts("\r\n");
    }
    for (;;) {
      r = read(fd,filebuf,sizeof filebuf);
      if (r == -1) _exit(23);
      if (r == 0) break;
      out_put(filebuf,r);
    }
  } else
  if (1 == level || 3 == level) {
    /* At level 1 and 3, send the file data fixing up every record. */
    char fbuf[BUFFER_INSIZE];
    buffer file = BUFFER_INIT(buffer_unixread,fd,fbuf,sizeof fbuf);

    if (protocol > 0)
      out_puts("+""-1\r\n");
    while (readline2(&file,&record)) {
      int req_field_num;
      unsigned int i;

      if (!stralloc_copys(&name_field,"")) _exit(21);
      if (!stralloc_copys(&path_field,"")) _exit(21);
      if (!stralloc_copys(&host_field,"")) _exit(21);
      if (!stralloc_copys(&port_field,"")) _exit(21);

      req_field_num = 0;
      for (i = 0;i < record.len;++i)
	if (record.s[i] == '\t') {
	  ++req_field_num;
	  if (req_field_num > 3) break;
	} else
	  switch(req_field_num) {
	    case 0:
	      if (!stralloc_append(&name_field,record.s + i)) _exit(21);
	      break;
	    case 1:
	      if (!stralloc_append(&path_field,record.s + i)) _exit(21);
	      break;
	    case 2:
	      if (!stralloc_append(&host_field,record.s + i)) _exit(21);
	      break;
	    case 3:
	      if (!stralloc_append(&port_field,record.s + i)) _exit(21);
	      break;
	  }

      if (3 == level)
	out_puts("+INFO: ");
      out_put(name_field.s,name_field.len);
      out_puts("\t");
      if (!path_field.len || '/' != path_field.s[0]) {
	if (path.len >= 1) {
	  if ('/' != path.s[0])
	    out_puts("/");
	  out_put(path.s,path.len);
	  if ('/' != path.s[path.len - 1])
	    out_puts("/");
	} else
	  out_puts("/");
      }
      out_put(path_field.s,path_field.len);
      out_puts("\t");
      if (host_field.len)
	out_put(host_field.s,host_field.len);
      else
	out_puts(localhost);
      out_puts("\t");
      if (port_field.len)
	out_put(port_field.s,port_field.len);
      else
	out_puts(localport);
      out_puts("\t");
      out_put(record.s + i,record.len - i);
      out_puts("\r\n");
    }
    if (protocol > 0)
      out_puts(".\r\n");
  } else
  if (2 == level) {
    /* At level 2, send the file metadata. */
    if (!stralloc_cats(&attr,"+INFO: 3bogus\t\t\t\t+\r\n+ADMIN:\r\n")) _exit(21);
    headers(&attr,&mtime,length,fn.s);
    if (!stralloc_cats(&attr,"\r\n")) _exit(21);

    if (protocol > 0) {
      out_puts("+");
      out_put(strnum,fmt_ulong(strnum,attr.len));
      out_puts("\r\n");
    }
    out_put(attr.s,attr.len);
  } else 
    barf(1, fn.s, "Internal error");

  out_flush();
  if (protocol < 1)
    _exit(0);
  close(fd);
}

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
static stralloc line = stralloc_static_0;

void readline(void)
{
  if (!readline2(&in,&line)) _exit(0);
}

void doit()
{
  sig_ignore(sig_pipe);

  localhost = ucspi_get_localhost_str(0, 0, 0);
  if (!localhost)
	  localhost = ucspi_get_localip_str("0", "0", "0");
  localport = ucspi_get_localport_str("70", "70", "70");

  for (;;) {
    int req_field_num;
    int flagdir;
    unsigned int i;

    readline();

    if (!stralloc_copys(&path,"")) _exit(21);
    if (!stralloc_copys(&plus,"")) _exit(21);
    if (!stralloc_copys(&rqdf,"")) _exit(21);
    level = 0;
    protocol = 0;
    flagmenu = 0;

    req_field_num = 0;
    for (i = 0;i < line.len;++i)
      if (line.s[i] == '\t') {
	++req_field_num;
	if (req_field_num > 2) break;
      }
      else
        switch(req_field_num) {
          case 0:
            if (!stralloc_append(&path,line.s + i)) _exit(21);
            break;
          case 1:
            if (!stralloc_append(&plus,line.s + i)) _exit(21);
            break;
          case 2:
            if (!stralloc_append(&rqdf,line.s + i)) _exit(21);
            break;
        }

    flagdir = path.len < 1 || '/' == path.s[path.len - 1];

    if (plus.len > 0) {
      if ('+' == plus.s[0]) {
	protocol = 1;
	if (flagdir) level = 1;
      } else
      if ('!' == plus.s[0]) {
        level = 2;
      } else
      if ('$' == plus.s[0]) {
	protocol = 1;
        level = 3;
	if (!flagdir)
	  goto no_protocol;
      } else {
no_protocol:
	if (!stralloc_0(&path)) _exit(21);
	barf(4, path.s, "protocol not implemented");
      }
    } else {
      if (flagdir) level = 1;
    }

    if (rqdf.len) {
      if (!stralloc_0(&rqdf)) _exit(21);
      if (!case_equals(rqdf.s,"0")) {
	if (!stralloc_0(&path)) _exit(21);
	barf(4, path.s, "this is a secure read-only server");
      }
    }

    if (!stralloc_copy(&file,&path)) _exit(21);
    if (flagdir) {
      if (!file.len) {
	if (!stralloc_append(&file,"/")) _exit(21);
      }
      if (!stralloc_cats(&file,"index.gopher")) _exit(21);
    }

    get();
  }
}
