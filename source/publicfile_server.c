#include "publicfile_server.h"
#include "timeoutread.h"
#include "timeoutwrite.h"
#include "buffer.h"
#include "getln.h"
#include "exit.h"

static int safewrite(int fd,const char *buf,int len)
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

void out_put_nvt(const char *s,int len)
{
  while (len > 0) {
    buffer_put(&out,s,1);
    if (*s == (char) 255) buffer_put(&out,s,1);
    ++s;
    --len;
  }
}

static int saferead(int fd,char *buf,int len)
{
  int r;
  out_flush();
  r = timeoutread(60,fd,buf,len);
  if (r <= 0) _exit(0);
  return r;
}

static char inbuf[BUFFER_INSIZE];
static buffer in = BUFFER_INIT(saferead,0,inbuf,sizeof inbuf);

void in_get_nvt(char *ch)
{
  for (;;) {
    buffer_get(&in,ch,1);
    if (*ch != (char) 255) return;
    buffer_get(&in,ch,1);
    if (*ch == (char) 255) return;

    if ((*ch == (char) 254) || (*ch == (char) 252))
      buffer_get(&in,ch,1);
    else if (*ch == (char) 253) {
      buffer_get(&in,ch,1);
      buffer_put(&out,"\377\374",2);
      buffer_put(&out,ch,1);
    }
    else if (*ch == (char) 251) {
      buffer_get(&in,ch,1);
      buffer_put(&out,"\377\376",2);
      buffer_put(&out,ch,1);
    }
  }
}

stralloc line = stralloc_static_0;

int readline2(buffer * pin, stralloc * pline)
{
  int match;

  if (getln(pin,pline,&match,'\n') == -1) _exit(21);
  if (!match) return 0;
  if (pline->len && (pline->s[pline->len - 1] == '\n')) --pline->len;
  if (pline->len && (pline->s[pline->len - 1] == '\r')) --pline->len;
  return 1;
}

int readline(void)
{
  return readline2(&in,&line);
}
