#include "buffer.h"
#include "qlog.h"
#include "ip.h"

static void put(char c)
{
  buffer_put(buffer_2,&c,1);
}

static void hex(unsigned char c)
{
  put("0123456789abcdef"[(c >> 4) & 15]);
  put("0123456789abcdef"[c & 15]);
}

static void octal(unsigned char c)
{
  put('\\');
  put('0' + ((c >> 6) & 7));
  put('0' + ((c >> 3) & 7));
  put('0' + (c & 7));
}

void qlog(const struct ip_address *ip,uint16 port,const char id[2],uint16 max,const char *q,const char qtype[2],const char *result)
{
  char ch;
  char ch2;
  char buf[IP_FMT];
  long l;

  l = ip_fmt(buf,ip,':');
  buffer_put(buffer_2,buf,l);
  while (l % 8) { put(' '); ++l; }
  put(' ');
  hex(port >> 8);
  hex(port & 255);
  put(':');
  hex(id[0]);
  hex(id[1]);
  put(':');
  hex(max >> 8);
  hex(max & 255);
  buffer_puts(buffer_2,result);
  hex(qtype[0]);
  hex(qtype[1]);
  put(' ');

  if (!*q)
    put('.');
  else
    for (;;) {
      ch = *q++;
      while (ch--) {
        ch2 = *q++;
        if ((ch2 >= 'A') && (ch2 <= 'Z'))
	  ch2 += 32;
        if (((ch2 >= 'a') && (ch2 <= 'z')) || ((ch2 >= '0') && (ch2 <= '9')) || (ch2 == '-') || (ch2 == '_'))
	  put(ch2);
        else
	  octal(ch2);
      }
      if (!*q) break;
      put('.');
    }

  put('\n');
  buffer_flush(buffer_2);
}
