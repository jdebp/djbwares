#include <unistd.h>
#include "droproot.h"
#include "exit.h"
#include "env.h"
#include "uint32.h"
#include "uint16.h"
#include "ip4.h"
#include "tai.h"
#include "buffer.h"
#include "timeoutread.h"
#include "timeoutwrite.h"
#include "open.h"
#include "seek.h"
#include "cdb.h"
#include "stralloc.h"
#include "strerr.h"
#include "str.h"
#include "byte.h"
#include "case.h"
#include "dns.h"
#include "scan.h"
#include "qlog.h"
#include "response.h"
#include "ucspi.h"

extern int respond(char *,char *,char *);

#define FATAL "axfrdns: fatal: "

static void fatal1sys(const char *msg0)
{
  const char *x, *y;

  x = ucspi_get_remoteip_str("0", "0", "0");
  y = ucspi_get_remoteport_str("0", "0", "0");
  strerr_die6sys(111,FATAL,x," ",y," ",msg0);
}
static void fatal1x(const char *msg0)
{
  const char *x, *y;

  x = ucspi_get_remoteip_str("0", "0", "0");
  y = ucspi_get_remoteport_str("0", "0", "0");
  strerr_die6x(111,FATAL,x," ",y," ",msg0);
}
static void fatal2x(const char *msg0,const char *msg1)
{
  const char *x, *y;

  x = ucspi_get_remoteip_str("0", "0", "0");
  y = ucspi_get_remoteport_str("0", "0", "0");
  strerr_die7x(111,FATAL,x," ",y," ",msg0,msg1);
}
static void nomem(void)
{
  fatal1x("out of memory");
}
static void die_truncated(void)
{
  fatal1x("truncated request");
}
static void die_netwrite(void)
{
  fatal1sys("unable to write to network: ");
}
static void die_netread(void)
{
  fatal1sys("unable to read from network: ");
}
static void die_outside(void)
{
  fatal1x("unable to locate information in data.cdb");
}
static void die_cdbread(void)
{
  fatal1sys("unable to read data.cdb: ");
}
static void die_cdbformat(void)
{
  fatal2x("unable to read data.cdb: ","format error");
}

static int safewrite(int fd,char *buf,unsigned int len)
{
  int w;

  w = timeoutwrite(60,fd,buf,len);
  if (w <= 0) die_netwrite();
  return w;
}

static char netwritespace[1024];
static buffer netwrite = BUFFER_INIT(safewrite,1,netwritespace,sizeof netwritespace);

static void print(char *buf,unsigned int len)
{
  char tcpheader[2];
  uint16_pack_big(tcpheader,len);
  buffer_put(&netwrite,tcpheader,2);
  buffer_put(&netwrite,buf,len);
  buffer_flush(&netwrite);
}

static char *axfr;
static char *axfrok;

static void axfrcheck(char *q)
{
  int i;
  int j;

  if (!axfr) return;

  i = j = 0;
  for (;;) {
    if (!axfr[i] || (axfr[i] == '/')) {
      if (i > j) {
        if (!dns_domain_fromdot(&axfrok,axfr + j,i - j)) nomem();
        if (dns_domain_equal(q,axfrok)) return;
      }
      j = i + 1;
    }
    if (!axfr[i]) break;
    ++i;
  }

  fatal1x("disallowed zone transfer request");
}

static char *zone;
static unsigned int zonelen;

static int fdcdb;
static buffer bcdb;
static char bcdbspace[1024];

static void get(char *buf,unsigned int len)
{
  int r;

  while (len > 0) {
    r = buffer_get(&bcdb,buf,len);
    if (r < 0) die_cdbread();
    if (!r) die_cdbformat();
    buf += r;
    len -= r;
  }
}

static char ip[4];
static unsigned long port;
static char clientloc[2];

static struct tai now;
static char data[32767];
static uint32 dlen;
static uint32 dpos;

static void copy(char *buf,unsigned int len)
{
  dpos = dns_packet_copy(data,dlen,dpos,buf,len);
  if (!dpos) die_cdbread();
}

static void doname(stralloc *sa)
{
  static char *d;
  dpos = dns_packet_getname(data,dlen,dpos,&d);
  if (!dpos) die_cdbread();
  if (!stralloc_catb(sa,d,dns_domain_length(d))) nomem();
}

static int build(stralloc *sa,char *q,int flagsoa,char id[2])
{
  unsigned int rdatapos;
  char misc[20];
  char type[2];
  char recordloc[2];
  char ttl[4];
  char ttd[8];
  struct tai cutoff;

  dpos = 0;
  copy(type,2);
  if (flagsoa) if (byte_diff(type,2,DNS_T_SOA)) return 0;
  if (!flagsoa) if (byte_equal(type,2,DNS_T_SOA)) return 0;

  if (!stralloc_copyb(sa,id,2)) nomem();
  if (!stralloc_catb(sa,"\204\000\0\0\0\1\0\0\0\0",10)) nomem();
  copy(misc,1);
  if ((misc[0] == '=' + 1) || (misc[0] == '*' + 1)) {
    --misc[0];
    copy(recordloc,2);
    if (byte_diff(recordloc,2,clientloc)) return 0;
  }
  if (misc[0] == '*') {
    if (flagsoa) return 0;
    if (!stralloc_catb(sa,"\1*",2)) nomem();
  }
  if (!stralloc_catb(sa,q,dns_domain_length(q))) nomem();
  if (!stralloc_catb(sa,type,2)) nomem();

  copy(ttl,4);
  copy(ttd,8);
  if (byte_diff(ttd,8,"\0\0\0\0\0\0\0\0")) {
    tai_unpack(ttd,&cutoff);
    if (byte_equal(ttl,4,"\0\0\0\0")) {
      if (tai_less(&cutoff,&now)) return 0;
      uint32_pack_big(ttl,2);
    }
    else
      if (!tai_less(&cutoff,&now)) return 0;
  }

  if (!stralloc_catb(sa,DNS_C_IN,2)) nomem();
  if (!stralloc_catb(sa,ttl,4)) nomem();
  if (!stralloc_catb(sa,"\0\0",2)) nomem();
  rdatapos = sa->len;

  if (byte_equal(type,2,DNS_T_SOA)) {
    doname(sa);
    doname(sa);
    copy(misc,20);
    if (!stralloc_catb(sa,misc,20)) nomem();
  }
  else if (byte_equal(type,2,DNS_T_NS) || byte_equal(type,2,DNS_T_PTR) || byte_equal(type,2,DNS_T_CNAME)) {
    doname(sa);
  }
  else if (byte_equal(type,2,DNS_T_MX)) {
    copy(misc,2);
    if (!stralloc_catb(sa,misc,2)) nomem();
    doname(sa);
  }
  else
    if (!stralloc_catb(sa,data + dpos,dlen - dpos)) nomem();

  if (sa->len > 65535) die_cdbformat();
  uint16_pack_big(sa->s + rdatapos - 2,sa->len - rdatapos);
  return 1;
}

static struct cdb c;
static char *q;
static stralloc soa;
static stralloc message;

static void doaxfr(char id[2])
{
  char key[512];
  uint32 klen;
  char num[4];
  uint32 eod;
  uint32 pos;
  int r;

  axfrcheck(zone);

  tai_now(&now);
  cdb_init(&c,fdcdb);

  byte_zero(clientloc,2);
  key[0] = 0;
  key[1] = '%';
  byte_copy(key + 2,4,ip);
  r = cdb_find(&c,key,6);
  if (!r) r = cdb_find(&c,key,5);
  if (!r) r = cdb_find(&c,key,4);
  if (!r) r = cdb_find(&c,key,3);
  if (!r) r = cdb_find(&c,key,2);
  if (r == -1) die_cdbread();
  if (r && (cdb_datalen(&c) == 2))
    if (cdb_read(&c,clientloc,2,cdb_datapos(&c)) == -1) die_cdbread();

  cdb_findstart(&c);
  for (;;) {
    r = cdb_findnext(&c,zone,zonelen);
    if (r == -1) die_cdbread();
    if (!r) die_outside();
    dlen = cdb_datalen(&c);
    if (dlen > sizeof data) die_cdbformat();
    if (cdb_read(&c,data,dlen,cdb_datapos(&c)) == -1) die_cdbformat();
    if (build(&soa,zone,1,id)) break;
  }

  cdb_free(&c);
  print(soa.s,soa.len);

  seek_begin(fdcdb);
  buffer_init(&bcdb,buffer_unixread,fdcdb,bcdbspace,sizeof bcdbspace);

  pos = 0;
  get(num,4); pos += 4;
  uint32_unpack(num,&eod);
  while (pos < 2048) { get(num,4); pos += 4; }

  while (pos < eod) {
    if (eod - pos < 8) die_cdbformat();
    get(num,4); pos += 4;
    uint32_unpack(num,&klen);
    get(num,4); pos += 4;
    uint32_unpack(num,&dlen);
    if (eod - pos < klen) die_cdbformat();
    pos += klen;
    if (eod - pos < dlen) die_cdbformat();
    pos += dlen;

    if (klen > sizeof key) die_cdbformat();
    get(key,klen);
    if (dlen > sizeof data) die_cdbformat();
    get(data,dlen);

    if ((klen > 1) && (key[0] == 0)) continue; /* location */
    if (klen < 1) die_cdbformat();
    if (dns_packet_getname(key,klen,0,&q) != klen) die_cdbformat();
    if (!dns_domain_suffix(q,zone)) continue;
    if (!build(&message,q,0,id)) continue;
    print(message.s,message.len);
  }

  print(soa.s,soa.len);
}

static void netread(char *buf,unsigned int len)
{
  int r;

  while (len > 0) {
    r = timeoutread(60,0,buf,len);
    if (r == 0) _exit(0);
    if (r < 0) die_netread();
    buf += r; len -= r;
  }
}

static char tcpheader[2];
static char buf[512];
static uint16 len;

static char seed[128];

int main(void)
{
  unsigned int pos;
  char header[12];
  char qtype[2];
  char qclass[2];
  const char *x;

  droproot(FATAL);
  dns_random_init(seed);

  axfr = env_get("AXFR");
  
  x = ucspi_get_remoteip_str(NULL, NULL, NULL);
  if (x && ip4_scan(x,ip))
    ;
  else
    byte_zero(ip,4);

  x = ucspi_get_remoteport_str("0", "0", "0");
  scan_ulong(x,&port);

  for (;;) {
    netread(tcpheader,2);
    uint16_unpack_big(tcpheader,&len);
    if (len > 512) fatal1x("excessively large request");
    netread(buf,len);

    pos = dns_packet_copy(buf,len,0,header,12); if (!pos) die_truncated();
    if (header[2] & 254) fatal1x("bogus query");
    if (header[4] || (header[5] != 1)) fatal1x("bogus query");

    pos = dns_packet_getname(buf,len,pos,&zone); if (!pos) die_truncated();
    zonelen = dns_domain_length(zone);
    pos = dns_packet_copy(buf,len,pos,qtype,2); if (!pos) die_truncated();
    pos = dns_packet_copy(buf,len,pos,qclass,2); if (!pos) die_truncated();

    if (byte_diff(qclass,2,DNS_C_IN))
      fatal1x("bogus query: bad class");

//  qlog(ip,port,header,zone,qtype," ");

    if (byte_equal(qtype,2,DNS_T_AXFR)) {
      case_lowerb(zone,zonelen);
      fdcdb = open_read("data.cdb");
      if (fdcdb == -1) die_cdbread();
      qlog(ip,port,header,zone,qtype," A ");
      doaxfr(header);
      close(fdcdb);
    }
    else {
      if (!response_query(zone,qtype,qclass)) nomem();
      response[2] |= 4;
      case_lowerb(zone,zonelen);
      response_id(header);
      response[3] &= ~128;
      if (!(header[2] & 1)) response[2] &= ~1;
      if (!respond(zone,qtype,ip)) {
	qlog(ip,port,header,zone,qtype," - ");
	die_outside();
      }
      print(response,response_len);
      qlog(ip,port,header,zone,qtype," + ");
    }
  }
}
