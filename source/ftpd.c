#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include "timeoutconn.h"
#include "timeoutaccept.h"
#include "timeoutread.h"
#include "timeoutwrite.h"
#include "substdio.h"
#include "fetch.h"
#include "pathdecode.h"
#include "file.h"
#include "sig.h"
#include "tai.h"
#include "stralloc.h"
#include "str.h"
#include "error.h"
#include "case.h"
#include "byte.h"
#include "env.h"
#include "fmt.h"
#include "scan.h"
#include "ip.h"
#include "ucspi.h"

long safewrite(int fd,char *buf,int len)
{
  int r;
  r = timeoutwrite(60,fd,buf,len);
  if (r <= 0) _exit(0);
  return r;
}

char outbuf[1024];
substdio out = SUBSTDIO_FDBUF(safewrite,1,outbuf,sizeof outbuf);

void out_flush(void)
{
  substdio_flush(&out);
}

void out_put(const char *s,int len)
{
  while (len > 0) {
    substdio_put(&out,s,1);
    if (*s == (char) 255) substdio_put(&out,s,1);
    ++s;
    --len;
  }
}

void out_puts(const char *s)
{
  out_put(s,str_len(s));
}

long saferead(int fd,char *buf,int len)
{
  int r;
  out_flush();
  r = timeoutread(60,fd,buf,len);
  if (r <= 0) _exit(0);
  return r;
}

char inbuf[512];
substdio in = SUBSTDIO_FDBUF(saferead,0,inbuf,sizeof inbuf);

void in_get(char *ch)
{
  for (;;) {
    substdio_get(&in,ch,1);
    if (*ch != (char) 255) return;
    substdio_get(&in,ch,1);
    if (*ch == (char) 255) return;

    if ((*ch == (char) 254) || (*ch == (char) 252))
      substdio_get(&in,ch,1);
    else if (*ch == (char) 253) {
      substdio_get(&in,ch,1);
      substdio_put(&out,"\377\374",2);
      substdio_put(&out,ch,1);
    }
    else if (*ch == (char) 251) {
      substdio_get(&in,ch,1);
      substdio_put(&out,"\377\376",2);
      substdio_put(&out,ch,1);
    }
  }
}

char strnum[FMT_ULONG];
struct ip_address iplocal = { {0,0,0,0} };
struct ip_address ipremote = { {0,0,0,0} };
struct sockaddr_in sa;

int fdlisten = -1; /* PASV socket; -1 if PASV not active */
unsigned int portremote = 0;
static int anonymous_login = 0;
static int epsv_only = 0;

stralloc host = stralloc_static_0;
stralloc dir = stralloc_static_0;
stralloc ndir = stralloc_static_0;
stralloc fn = stralloc_static_0;

void startlistening(unsigned char x[6])
{
  socklen_t dummy;
  int opt;

  if (fdlisten != -1) { close(fdlisten); fdlisten = -1; }

  byte_zero(&sa,sizeof sa);
  sa.sin_family = AF_INET;
  byte_copy(&sa.sin_addr,4,&iplocal);

  fdlisten = socket(AF_INET,SOCK_STREAM,0);
  if (fdlisten == -1) _exit(22);

  opt = 1;
  setsockopt(fdlisten,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof opt);
  if (bind(fdlisten,(struct sockaddr *) &sa,sizeof sa) == -1) _exit(22);
  if (listen(fdlisten,1) == -1) _exit(22);

  dummy = sizeof sa;
  if (getsockname(fdlisten,(struct sockaddr *) &sa,&dummy) == -1) _exit(22);

  byte_copy(x,4,&sa.sin_addr);
  byte_copy(x + 4,2,&sa.sin_port);
}

void spsv(void)
{
  unsigned char x[6];

  if (epsv_only) {
    out_puts("503 You promised EPSV only.\r\n");
    return;
  }

  startlistening(x);

  out_puts("227 ");
  out_put(strnum,fmt_ulong(strnum,x[4] * (unsigned long) 256 + x[5]));
  out_puts("\r\n");
}

void pasv(void)
{
  unsigned char x[6];

  if (epsv_only) {
    out_puts("503 You promised EPSV only.\r\n");
    return;
  }

  startlistening(x);

  /* The = character is, per Bernstein, a bodge for Netscape.
  ** The brackets are a bodge for Firefox, its descendant.
  ** Yes, Firefox violates RFC 1123 section 4.1.2.6 .
  ** It fails to parse the bracketless form if given it.
  */
  out_puts("227 =(");
  out_put(strnum,fmt_ulong(strnum,(unsigned long) x[0]));
  out_puts(",");
  out_put(strnum,fmt_ulong(strnum,(unsigned long) x[1]));
  out_puts(",");
  out_put(strnum,fmt_ulong(strnum,(unsigned long) x[2]));
  out_puts(",");
  out_put(strnum,fmt_ulong(strnum,(unsigned long) x[3]));
  out_puts(",");
  out_put(strnum,fmt_ulong(strnum,(unsigned long) x[4]));
  out_puts(",");
  out_put(strnum,fmt_ulong(strnum,(unsigned long) x[5]));
  out_puts(")\r\n");
}

void epsv(const char *arg)
{
  unsigned char x[6];

  if (*arg) {
    if (case_equals(arg,"all")) { 
      epsv_only = 1;
    } else if (!case_equals(arg,"1")) { 
      out_puts("504 I do not do that IP protocol.\r\n");
      return; 
    }
  }

  startlistening(x);

  out_puts("229 =(|||");
  out_put(strnum,fmt_ulong(strnum,(unsigned long)x[4] * 256U + x[5]));
  out_puts("|)\r\n");
}

int portparse(char *arg,unsigned char x[6])
{
  unsigned int i;
  unsigned long u;

  i = scan_ulong(arg,&u); if (!i) return 0; x[0] = u;
  arg += i; if (*arg++ != ',') return 0;
  i = scan_ulong(arg,&u); if (!i) return 0; x[1] = u;
  arg += i; if (*arg++ != ',') return 0;
  i = scan_ulong(arg,&u); if (!i) return 0; x[2] = u;
  arg += i; if (*arg++ != ',') return 0;
  i = scan_ulong(arg,&u); if (!i) return 0; x[3] = u;
  arg += i; if (*arg++ != ',') return 0;
  i = scan_ulong(arg,&u); if (!i) return 0; x[4] = u;
  arg += i; if (*arg++ != ',') return 0;
  i = scan_ulong(arg,&u); if (!i) return 0; x[5] = u;
  return 1;
}

void port(char *arg)
{
  unsigned char x[6];

  if (fdlisten != -1) { close(fdlisten); fdlisten = -1; }

  if (!portparse(arg,x)) {
    out_puts("501 Sorry, you need to give me six numbers separated by commas.\r\n");
    return;
  }
  if (x[4] < 4) {
    out_puts("501 Sorry, I don't accept port numbers below 1024.\r\n");
    return;
  }
  if (byte_diff(x,4,&ipremote)) {
    out_puts("501 Sorry, I don't allow PORT relaying.\r\n");
    return;
  }

  portremote = x[4] * (unsigned int) 256 + x[5];
  out_puts("200 Okay.\r\n");
}

void rest(char *arg)
{
  scan_ulong(arg,&fetch_rest);
  out_puts("350 Okay.\r\n");
}

void get(char *arg,int how)
{
  int fdfile;
  int fddata;
  struct tai mtime;
  unsigned long length;
  int dummy;

  if (!stralloc_copys(&fn,"./")) _exit(21);
  if (!stralloc_cat(&fn,&host)) _exit(21);
  if (!stralloc_cats(&fn,"/")) _exit(21);
  if (*arg != '/') {
    if (!stralloc_cat(&fn,&dir)) _exit(21);
    if (!stralloc_append(&fn,"/")) _exit(21);
  }
  if (!stralloc_cats(&fn,arg)) _exit(21);
  pathdecode(&fn);
  if (!stralloc_0(&fn)) _exit(21);

  fdfile = file_open(fn.s,&mtime,&length,how == FETCH_RETR,FETCH_LIST == how || FETCH_NLST == how,FETCH_NLST == how ? 2 : FETCH_LIST == how ? 3 : 0);
  if (fdfile == -1) {
    out_puts("550 Sorry, I can't open that file: ");
    out_puts(error_str(errno));
    out_puts(".\r\n");
    return;
  }

  out_puts("150 ");
  if ((how == FETCH_RETR) && fetch_ascii)
    out_puts("Warning: You're using ASCII! ");

  if (fdlisten == -1) {
    out_puts("Making transfer connection...\r\n");
    out_flush();

    fddata = socket(AF_INET,SOCK_STREAM,0);
    if (fddata == -1) _exit(22);

    /* kernel will reject port 0 at this point */
    if (timeoutconn(fddata,&ipremote,portremote,60) == -1) {
      close(fddata);
      close(fdfile);
      out_puts("425 Sorry, I couldn't make a connection: ");
      out_puts(error_str(errno));
      out_puts(".\r\n");
      return;
    }
  }
  else {
    out_puts("Waiting for transfer connection...\r\n");
    out_flush();

    fddata = timeoutaccept(fdlisten,60);
    close(fdlisten); fdlisten = -1;

    if (fddata != -1) {
      dummy = sizeof sa;
      if (getpeername(fddata,(struct sockaddr *) &sa,&dummy) == -1) {
        close(fddata); fddata = -1;
      }
      else if (byte_diff(&sa.sin_addr,4,&ipremote)) {
	errno = error_acces;
	close(fddata); fddata = -1;
      }
    }

    if (fddata == -1) {
      close(fdfile);
      out_puts("425 Sorry, I couldn't accept a connection: ");
      out_puts(error_str(errno));
      out_puts(".\r\n");
      return;
    }
  }

  dummy = 1;
  setsockopt(fddata,IPPROTO_TCP,1/*TCP_NODELAY*/,&dummy,sizeof dummy);

  fetch(arg,fddata,fdfile,how); /* closes fddata and fdfile */

  portremote = 0;
}

void dir_moveup(void)
{
  if (!stralloc_copy(&ndir,&dir)) _exit(21);
  ndir.len = byte_rchr(ndir.s,ndir.len,'/');
}

void dir_move(const char *to)
{
  if (*to == '/') {
    if (!stralloc_copys(&ndir,"")) _exit(21);
    ++to;
  } else
    if (!stralloc_copy(&ndir,&dir)) _exit(21);
  if (*to) {
    if (!stralloc_append(&ndir,"/")) _exit(21);
    if (!stralloc_cats(&ndir,to)) _exit(21);
  }
}

int ok_dir()
{
  int fdfile;
  struct tai mtime;
  unsigned long length;

  if (!stralloc_copys(&fn,"./")) _exit(21);
  if (!stralloc_cat(&fn,&host)) _exit(21);
  if (!stralloc_cats(&fn,"/")) _exit(21);
  if (!stralloc_cat(&fn,&ndir)) _exit(21);
  if (!stralloc_append(&fn,"/")) _exit(21);
  pathdecode(&fn);
  if (!stralloc_0(&fn)) _exit(21);

  fdfile = file_open(fn.s,&mtime,&length,0,1,1);
  if (fdfile == -1) {
    out_puts("550 Sorry, I can't use that directory: ");
    out_puts(error_str(errno));
    out_puts(".\r\n");
    return 0;
  }
  close(fdfile);
  if (!stralloc_copy(&dir,&ndir)) _exit(21);
  return 1;
}

void say_dir(const char *code)
{
  unsigned int i;
  char ch;

  out_puts(code);
  out_puts("\"");
  if (!dir.len)
    out_puts("/");
  else
    for (i = 0;i < dir.len;++i) {
      ch = dir.s[i];
      if (ch == '\n') out_put("",1);
      else if (ch == '"') out_put("\"\"",2);
      else out_put(&ch,1);
    }
  out_puts("\" \r\n");
}

void cwd(const char *arg) 
{
  dir_move(arg);
  if (!ok_dir()) return;
  say_dir("250 ");
}

void cdup()
{
  dir_moveup();
  if (!ok_dir()) return;
  say_dir("200 ");
}

void vhost(const char *h)
{
  if (!*h) {
    out_puts("501 bad virtual host\r\n");
    return;
  }
  if (!stralloc_copys(&host,h)) _exit(21);
  case_lowerb(host.s,host.len);
  out_puts("220 virtual host accepted\r\n");
}

void request(char *cmd,char *arg)
{
  if (case_equals(cmd,"spsv")) { spsv(); return; }
  if (case_equals(cmd,"pasv")) { pasv(); return; }
  if (case_equals(cmd,"epsv")) { epsv(arg); return; }
  if (case_equals(cmd,"port")) { port(arg); return; }
  if (case_equals(cmd,"rest")) { rest(arg); return; }
  if (case_equals(cmd,"host")) { vhost(arg); return; }
  if (case_equals(cmd,"retr")) { get(arg,FETCH_RETR); return; }
  if (case_equals(cmd,"list")) { get(arg,*arg ? FETCH_LISTONE : FETCH_LIST); return; }
  if (case_equals(cmd,"nlst")) { get(arg,FETCH_NLST); return; }
  if (case_equals(cmd,"feat")) {	/* RFC 2389 */
    out_puts("211-I understand:\r\n"
             " PIPELINING\r\n"	/* http://cr.yp.to/ftp/pipelining.html */
             " EPLF\r\n"	/* http://cr.yp.to/ftp/list/eplf.html */
             " HOST\r\n"	/* RFC 7151 */
             " TVFS\r\n"	/* RFC 3659 */
             "211 .\r\n");
    return;
  }
  if (case_equals(cmd,"opts")) {	/* RFC 2389 */
    out_puts("501 No options are available.\r\n");
    return;
  }
  if (case_equals(cmd,"size")) {	/* RFC 3659 */
    /* Respond 502 to this, and Google Chrome ups and quits the entire session.
    */
    out_puts("550 Check the result of FEAT first, as RFC 3659 instructs.\r\n");
    return;
  }
  if (case_equals(cmd,"quit")) {
    out_puts("221 Bye.\r\n");
    out_flush();
    _exit(0);
  }
  if (case_equals(cmd,"user")) {
    /* The Bernstein original returned 230 here.
    ** Whilst conformant to the protocol, this confused the heck out of certain FTP application-level gateways in routers.
    ** The FTP ALGs did not understand that USER could return a 2xx rather than a 3xx.
    */
    anonymous_login = case_equals(arg,"anonymous");
    out_puts(anonymous_login ? "331" : "230");
    out_puts(" Hi. No need to log in; I'm an anonymous ftp server.\r\n");
    return;
  }
  if (case_equals(cmd,"pass")) {
    /* The Bernstein original returned 202 here.
    ** Whilst conformant to the protocol, this confused the heck out of certain FTP application-level gateways in routers.
    ** The FTP ALGs did not understand that PASS could be superfluous.
    */
    out_puts(anonymous_login ? "230" : "202");
    out_puts(" Hi. No need to log in; I'm an anonymous ftp server.\r\n");
    return;
  }
  if (case_equals(cmd,"acct")) {
    out_puts("202 I don't need account information; I'm an anonymous FTP server.\r\n");
    return;
  }
  if (case_equals(cmd,"noop")) {
    out_puts("200 I'm here.\r\n");
    return;
  }
  if (case_equals(cmd,"pwd") || case_equals(cmd,"xpwd")) {
    say_dir("257 ");
    return;
  }
  if (case_equals(cmd,"cwd") || case_equals(cmd,"xcwd")) { cwd(arg); return; }
  if (case_equals(cmd,"cdup") || case_equals(cmd,"xcup")) { cdup(); return; }
  if (case_equals(cmd,"stru")) {
    if ((*arg == 'f') || (*arg == 'F')) {
      out_puts("200 Thanks, I always do file structure.\r\n");
      return;
    }
    out_puts("504 Sorry, I don't do anything except file structure.\r\n");
    return;
  }
  if (case_equals(cmd,"mode")) {
    if ((*arg == 's') || (*arg == 'S')) {
      out_puts("200 Thanks, I always do stream mode.\r\n");
      return;
    }
    out_puts("504 Sorry, I don't do anything except stream mode.\r\n");
    return;
  }
  if (case_equals(cmd,"type")) {
    if ((*arg == 'a') || (*arg == 'A')) {
      fetch_ascii = 1;
      out_puts("200 Why are you using ASCII?\r\n");
      return;
    }
    if ((*arg == 'i') || (*arg == 'I') || (*arg == 'l') || (*arg == 'L')) {
      fetch_ascii = 0;
      out_puts("200 Okay, using binary.\r\n");
      return;
    }
    out_puts("504 Sorry, I don't recognize that type.\r\n");
    return;
  }
  if (case_equals(cmd,"syst")) {
    /* See http://cr.yp.to/ftp/syst.html for the rationale. */
    out_puts("215 UNIX Type: L8\r\n");
    return;
  }
  if (case_equals(cmd,"help")) {
    out_puts("214-See these:\r\n"
             " Daniel J. Bernstein's FTP doco: http://cr.yp.to/ftp.html\r\n"
             " publicfile home page: http://cr.yp.to/publicfile.html\r\n"
             " djbwares home page: http://jdebp.eu./Source/djbwares/\r\n"
	     "214 .\r\n");
    return;
  }
  if (case_equals(cmd,"allo")) {
    out_puts("202 Who cares? I don't allow file creation.\r\n");
    return;
  }
  if (case_equals(cmd,"stor") || case_equals(cmd,"stou") || case_equals(cmd,"appe") || case_equals(cmd,"dele") || case_equals(cmd,"rnfr") || case_equals(cmd,"rnto") || case_equals(cmd,"mkd") || case_equals(cmd,"xmkd") || case_equals(cmd,"rmd") || case_equals(cmd,"xrmd")) {
    out_puts("553 Sorry, I don't allow file modification.\r\n");
    return;
  }

  out_puts("502 Sorry, I don't understand that command.\r\n");
}

stralloc line = stralloc_static_0;

void doit(void)
{
  char *cmd;
  char *arg;
  const char *x;
  unsigned char ch;

  {
    int opt = 1;
    setsockopt(0,SOL_SOCKET,SO_OOBINLINE,(char *) &opt,sizeof opt);
    /* if it fails, bummer */
  }

  x = ucspi_get_localhost_str(NULL, NULL, NULL);
  if (!x) x = "0";
  if (!stralloc_copys(&host,x)) _exit(21);

  x = ucspi_get_localip_str(NULL, NULL, NULL);
  if (!x || !ip_scan(x,&iplocal))
    byte_zero(&iplocal,4);

  x = ucspi_get_remoteip_str(NULL, NULL, NULL);
  if (!x || !ip_scan(x,&ipremote))
    byte_zero(&ipremote,4);

  if (!stralloc_copys(&dir,"")) _exit(21);

  sig_ignore(sig_pipe);

  for (;;) {
    if (!stralloc_copys(&line,"")) _exit(21);
    for (;;) {
      in_get(&ch);
      if (ch == '\n') break;
      if (!ch) ch = '\n';
      if (!stralloc_append(&line,&ch)) _exit(21);
    }
    if (line.len && (line.s[line.len - 1] == '\r')) --line.len;
    if (!stralloc_0(&line)) _exit(21);

    cmd = line.s;
    arg = cmd + str_chr(cmd,' ');
    if (*arg) *arg++ = 0;

    request(cmd,arg);
  }
}
