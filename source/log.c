#include "buffer.h"
#include "uint32.h"
#include "uint16.h"
#include "error.h"
#include "byte.h"
#include "dns.h"
#include "log.h"

/* work around gcc 2.95.2 bug */
#define number(x) ( (u64 = (x)), u64_print() )
static uint64 u64;
static void u64_print(void)
{
  char buf[20];
  unsigned int pos;

  pos = sizeof buf;
  do {
    if (!pos) break;
    buf[--pos] = '0' + (u64 % 10);
    u64 /= 10;
  } while(u64);

  buffer_put(buffer_2,buf + pos,sizeof buf - pos);
}

static void hex(unsigned char c)
{
  buffer_put(buffer_2,&"0123456789abcdef"[c >> 4],1);
  buffer_put(buffer_2,&"0123456789abcdef"[c & 15],1);
}

static void string(const char *s)
{
  buffer_puts(buffer_2,s);
}

static void character(const char c)
{
  buffer_PUTC(buffer_2,c);
}

static void line(void)
{
  string("\n");
  buffer_flush(buffer_2);
}

static void space(void)
{
  string(" ");
}

static void ip4(const char *buf, unsigned int len)
{
  unsigned int i;

  for (i = 0;i < 4;++i) {
    if (i >= len)
      string("?");
    else
      hex(buf[i]);
  }
}

static void ip6(const char *buf, unsigned int len)
{
  unsigned int i;

  for (i = 0;i < 16;++i) {
    if (i >= len)
      string("??");
    else
      hex(buf[i]);
    if (i & 1 && i < 15)
      character(':');
  }
}

static void logid(const char id[2])
{
  hex(id[0]);
  hex(id[1]);
}

static void logtype(const char type[2])
{
  if (byte_equal(type,2,DNS_T_A)) string("a");
  else if (byte_equal(type,2,DNS_T_AAAA)) string("aaaa");
  else if (byte_equal(type,2,DNS_T_TXT)) string("txt");
  else if (byte_equal(type,2,DNS_T_MX)) string("mx");
  else if (byte_equal(type,2,DNS_T_SOA)) string("soa");
  else if (byte_equal(type,2,DNS_T_CNAME)) string("cname");
  else if (byte_equal(type,2,DNS_T_PTR)) string("ptr");
  else if (byte_equal(type,2,DNS_T_SIG)) string("sig");
  else if (byte_equal(type,2,DNS_T_SRV)) string("srv");
  else {
    uint16 u;

    uint16_unpack_big(type,&u);
    number(u);
  }
}

static void name(const char *q)
{
  char ch;
  int state;

  if (!*q) {
    string(".");
    return;
  }
  while ((state = *q++)) {
    while (state) {
      ch = *q++;
      --state;
      if ((ch <= 32) || (ch > 126)) ch = '?';
      if ((ch >= 'A') && (ch <= 'Z')) ch += 32;
      buffer_put(buffer_2,&ch,1);
    }
    string(".");
  }
}

static void u16p(const char * buf, unsigned int len, unsigned int off)
{
  if (off + 2 >= len) {
    string("?");
  } else {
    uint16 u;
    uint16_unpack_big(buf + off,&u);
    u64 = u;
    u64_print();
  }
}

static void namep(const char * buf, unsigned int len, unsigned int off)
{
  if (off >= len) {
    string("?");
  } else {
    name(buf + off);
  }
}

void log_startup(void)
{
  string("starting");
  line();
}

void log_query(uint64 *qnum,const char client[4],unsigned int port,const char id[2],const char *q,const char qtype[2])
{
  string("query "); number(*qnum); space();
  ip4(client,4); string(":"); hex(port >> 8); hex(port & 255);
  string(":"); logid(id); space();
  logtype(qtype); space(); name(q);
  line();
}

void log_querydone(uint64 *qnum,unsigned int len)
{
  string("sent "); number(*qnum); space();
  number(len);
  line();
}

void log_querydrop(uint64 *qnum)
{
  const char *x = error_str(errno);

  string("drop "); number(*qnum); space();
  string(x);
  line();
}

void log_tcpopen(const char client[4],unsigned int port)
{
  string("tcpopen ");
  ip4(client,4); string(":"); hex(port >> 8); hex(port & 255);
  line();
}

void log_tcpclose(const char client[4],unsigned int port)
{
  const char *x = error_str(errno);
  string("tcpclose ");
  ip4(client,4); string(":"); hex(port >> 8); hex(port & 255); space();
  string(x);
  line();
}

void log_tx(const char *q,const char qtype[2],const char *control,const char servers[64],unsigned int gluelessness)
{
  int i;

  string("tx "); number(gluelessness); space();
  logtype(qtype); space(); name(q); space();
  name(control);
  for (i = 0;i < 64;i += 4)
    if (byte_diff(servers + i,4,"\0\0\0\0")) {
      space();
      ip4(servers + i, 4);
    }
  line();
}

void log_cachedanswer(const char *q,const char type[2])
{
  string("cached "); logtype(type); space();
  name(q);
  line();
}

void log_cachedcname(const char *dn,const char *dn2)
{
  string("cached cname "); name(dn); space(); name(dn2);
  line();
}

void log_cachedns(const char *control,const char *ns)
{
  string("cached ns "); name(control); space(); name(ns);
  line();
}

void log_cachednxdomain(const char *dn)
{
  string("cached nxdomain "); name(dn);
  line();
}

void log_nxdomain(const char server[4],const char *q,unsigned int ttl)
{
  string("nxdomain "); ip4(server,4); space(); number(ttl); space();
  name(q);
  line();
}

void log_nodata(const char server[4],const char *q,const char qtype[2],unsigned int ttl)
{
  string("nodata "); ip4(server,4); space(); number(ttl); space();
  logtype(qtype); space(); name(q);
  line();
}

void log_lame(const char server[4],const char *control,const char *referral)
{
  string("lame "); ip4(server,4); space();
  name(control); space(); name(referral);
  line();
}

void log_ignore_referral(const char server[4],const char * control, const char *referral)
{
  string("ignored referral "); ip4(server,4); space();
  name(control); space(); name(referral);
  line();
}

void log_servfail(const char *dn)
{
  const char *x = error_str(errno);

  string("servfail "); name(dn); space();
  string(x);
  line();
}

void log_rr(const char server[4],const char *q,const char type[2],const char *buf,unsigned int len,unsigned int ttl)
{
  unsigned int i;

  string("rr "); ip4(server,4); space(); number(ttl); space();
  logtype(type); space(); name(q); space();

  if (byte_equal(type,2,DNS_T_SRV)) {
    u16p(buf,len,4); space();
    u16p(buf,len,0); space();
    u16p(buf,len,2); space();
    namep(buf,len,6);
  } else if (byte_equal(type,2,DNS_T_A)) {
    ip4(buf, len);    
  } else if (byte_equal(type,2,DNS_T_AAAA)) {
    ip6(buf, len);
  } else {
    for (i = 0;i < len;++i) {
      hex(buf[i]);
      if (i > 30) {
	string("...");
	break;
      }
    }
  }
  line();
}

void log_rrns(const char server[4],const char *q,const char *data,unsigned int ttl)
{
  string("rr "); ip4(server,4); space(); number(ttl);
  string(" ns "); name(q); space();
  name(data);
  line();
}

void log_rrcname(const char server[4],const char *q,const char *data,unsigned int ttl)
{
  string("rr "); ip4(server,4); space(); number(ttl);
  string(" cname "); name(q); space();
  name(data);
  line();
}

void log_rrptr(const char server[4],const char *q,const char *data,unsigned int ttl)
{
  string("rr "); ip4(server,4); space(); number(ttl);
  string(" ptr "); name(q); space();
  name(data);
  line();
}

void log_rrmx(const char server[4],const char *q,const char *mx,const char pref[2],unsigned int ttl)
{
  uint16 u;

  string("rr "); ip4(server,4); space(); number(ttl);
  string(" mx "); name(q); space();
  uint16_unpack_big(pref,&u);
  number(u); space(); name(mx);
  line();
}

void log_rrsoa(const char server[4],const char *q,const char *n1,const char *n2,const char misc[20],unsigned int ttl)
{
  uint32 u;
  int i;

  string("rr "); ip4(server,4); space(); number(ttl);
  string(" soa "); name(q); space();
  name(n1); space(); name(n2);
  for (i = 0;i < 20;i += 4) {
    uint32_unpack_big(misc + i,&u);
    space(); number(u);
  }
  line();
}

void log_stats(void)
{
  extern uint64 numqueries;
  extern uint64 cache_motion;
  extern int uactive;
  extern int tactive;

  string("stats ");
  number(numqueries); space();
  number(cache_motion); space();
  number(uactive); space();
  number(tactive);
  line();
}
