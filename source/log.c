#include "buffer.h"
#include "uint32.h"
#include "uint16.h"
#include "error.h"
#include "mem.h"
#include "dns_constants.h"
#include "dns_packet.h"
#include "log.h"
#include "ip.h"
#include "dnscache.h"

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

static void ip(const struct ip_address *ip)
{
  char buf[IP_FMT];
  buffer_put(buffer_2,buf,ip_fmt(buf,ip,':'));
}

static void logid(const char id[2])
{
  hex(id[0]);
  hex(id[1]);
}

static void logtype(const char type[2])
{
  if (dns_packet_typematch(type,DNS_T_A)) string("a");
  else if (dns_packet_typematch(type,DNS_T_AAAA)) string("aaaa");
  else if (dns_packet_typematch(type,DNS_T_TXT)) string("txt");
  else if (dns_packet_typematch(type,DNS_T_MX)) string("mx");
  else if (dns_packet_typematch(type,DNS_T_SOA)) string("soa");
  else if (dns_packet_typematch(type,DNS_T_CNAME)) string("cname");
  else if (dns_packet_typematch(type,DNS_T_PTR)) string("ptr");
  else if (dns_packet_typematch(type,DNS_T_SIG)) string("sig");
  else if (dns_packet_typematch(type,DNS_T_SRV)) string("srv");
  else if (dns_packet_typematch(type,DNS_T_LOC)) string("loc");
  else if (dns_packet_typematch(type,DNS_T_OPT)) string("opt");
  else if (dns_packet_typematch(type,DNS_T_HTTPS)) string("https");
  else if (dns_packet_typematch(type,DNS_T_SVCB)) string("svcb");
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

void log_query(uint64 *qnum,const struct ip_address * client,unsigned int port,const char id[2],const char *q,const char qtype[2],unsigned int max)
{
  string("query "); number(*qnum); space();
  ip(client); space();
  hex(port >> 8); hex(port & 255); string(":"); logid(id); string(":"); hex(max >> 8); hex(max & 255); space();
  logtype(qtype); space();
  name(q);
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

void log_tcpopen(const struct ip_address *client,unsigned int port)
{
  string("tcpopen ");
  ip(client); string(":"); hex(port >> 8); hex(port & 255);
  line();
}

void log_tcpclose(const struct ip_address *client,unsigned int port)
{
  const char *x = error_str(errno);
  string("tcpclose ");
  ip(client); string(":"); hex(port >> 8); hex(port & 255); space();
  string(x);
  line();
}

void log_tx(const char *q,const char qtype[2],const char *control,const struct ip_address servers[16],unsigned int gluelessness)
{
  int i;

  string("tx "); number(gluelessness); space();
  logtype(qtype); space(); name(q); space();
  name(control);
  for (i = 0;i < 16;i += 1)
    if (!ip_is_unassigned(servers + i)) {
      space();
      ip(servers + i);
    }
  line();
}

void log_root(const char *q,const char qtype[2],const char *control,unsigned int gluelessness)
{
  string("root "); number(gluelessness); space();
  logtype(qtype); space(); name(q); space();
  name(control);
  line();
}

void log_want(const char *q,const char type[2],unsigned int gluelessness,unsigned int loopcount)
{
  string("want "); number(gluelessness); space(); number(loopcount); space();
  logtype(type); space(); name(q);
  line();
}

void log_synthetic(const char *q,const char type[2],unsigned int gluelessness,unsigned int ttl)
{
  string("synthetic ");
  number(gluelessness); space(); number(ttl); space(); logtype(type); space(); name(q);
  line();
}

void log_cachedanswer(const char *q,const char type[2],unsigned int ttl)
{
  string("cached ");
  number(ttl); space(); logtype(type); space(); name(q);
  line();
}

void log_cachedcname(const char *dn,const char *dn2,unsigned int ttl)
{
  string("cached cname ");
  number(ttl); space(); name(dn); space(); name(dn2);
  line();
}

void log_cachedns(const char *control,const char *ns,unsigned int ttl)
{
  string("cached nameserver ");
  number(ttl); space(); name(control); space(); name(ns);
  line();
}

void log_cachedglue(const char *ns,const struct ip_address * a,unsigned int ttl)
{
  string("cached address ");
  number(ttl); space(); name(ns); space(); ip(a);
  line();
}

void log_cachednxdomain(const char *dn,unsigned int ttl)
{
  string("cached nxdomain ");
  number(ttl); space(); name(dn);
  line();
}

void log_nxdomain(const struct ip_address *server,const char *q,unsigned int ttl)
{
  string("nxdomain ");
  ip(server); space(); number(ttl); space(); name(q);
  line();
}

void log_nodata(const struct ip_address *server,const char *q,const char qtype[2],unsigned int ttl)
{
  string("nodata ");
  ip(server); space(); number(ttl); space(); logtype(qtype); space(); name(q);
  line();
}

void log_lame(const struct ip_address *server,const char *control,const char *referral)
{
  string("lame "); ip(server); space();
  name(control); space(); name(referral);
  line();
}

void log_ignore_referral(const struct ip_address *server,const char * control, const char *referral,unsigned int gluelessness)
{
  string("ignored referral "); number(gluelessness); space();
  ip(server); space(); name(control); space(); name(referral);
  line();
}

void log_referral(const struct ip_address *server,const char * control, const char *referral,unsigned int gluelessness)
{
  string("referral "); number(gluelessness); space();
  ip(server); space(); name(control); space(); name(referral);
  line();
}

void log_servfail(const char *dn)
{
  const char *x = error_str(errno);

  string("servfail "); name(dn); space();
  string(x);
  line();
}

void log_no_servers(const char *dn)
{
  string("noservers "); name(dn);
  line();
}

void log_rr(const struct ip_address *server,const char *q,const char type[2],const char *buf,unsigned int len,unsigned int ttl)
{
  unsigned int i;

  string("rr "); ip(server); space(); number(ttl); space();
  logtype(type); space(); name(q); space();

  if (dns_packet_typematch(type,DNS_T_SRV)) {
    u16p(buf,len,4); space();
    u16p(buf,len,0); space();
    u16p(buf,len,2); space();
    namep(buf,len,6);
  } else if (dns_packet_typematch(type,DNS_T_A)) {
    struct ip_address a;
    char b[IP4_LEN] = {};
    if (len < sizeof b) character('?');
    mem_copy(b, len < sizeof b ? len : sizeof b, buf);
    ip_make4(&a,b);
    ip(&a);
  } else if (dns_packet_typematch(type,DNS_T_AAAA)) {
    struct ip_address a;
    char b[IP6_SANS_SCOPE_LEN] = {};
    if (len < sizeof b) character('?');
    mem_copy(b, len < sizeof b ? len : sizeof b, buf);
    ip_make6(&a,b,0);
    ip(&a);
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

void log_rrns(const struct ip_address *server,const char *q,const char *data,unsigned int ttl)
{
  string("rr "); ip(server); space(); number(ttl);
  string(" ns "); name(q); space();
  name(data);
  line();
}

void log_rrcname(const struct ip_address *server,const char *q,const char *data,unsigned int ttl)
{
  string("rr "); ip(server); space(); number(ttl);
  string(" cname "); name(q); space();
  name(data);
  line();
}

void log_rrptr(const struct ip_address *server,const char *q,const char *data,unsigned int ttl)
{
  string("rr "); ip(server); space(); number(ttl);
  string(" ptr "); name(q); space();
  name(data);
  line();
}

void log_rrmx(const struct ip_address *server,const char *q,const char *mx,const char pref[2],unsigned int ttl)
{
  uint16 u;

  string("rr "); ip(server); space(); number(ttl);
  string(" mx "); name(q); space();
  uint16_unpack_big(pref,&u);
  number(u); space(); name(mx);
  line();
}

void log_rrsoa(const struct ip_address *server,const char *q,const char *n1,const char *n2,const char misc[20],unsigned int ttl)
{
  uint32 u;
  int i;

  string("rr "); ip(server); space(); number(ttl);
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

  string("stats ");
  number(numqueries); space();
  number(cache_motion); space();
  number(uactive); space();
  number(tactive);
  line();
}
