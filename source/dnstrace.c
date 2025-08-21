#include "uint16.h"
#include "uint32.h"
#include "fmt.h"
#include "str.h"
#include "byte.h"
#include "ip.h"
#include "gen_alloc.h"
#include "gen_allocdefs.h"
#include "exit.h"
#include "buffer.h"
#include "stralloc.h"
#include "error.h"
#include "strerr.h"
#include "iopause.h"
#include "printrecord.h"
#include "alloc.h"
#include "parsetype.h"
#include "dd.h"
#include "dns_resolve.h"
#include "dns_transmit.h"
#include "dns_random.h"
#include "dns_domain.h"
#include "dns_packet.h"

#define FATAL "dnstrace: fatal: "

void nomem(void)
{
  strerr_die2x(111,FATAL,"out of memory");
}
void usage(void)
{
  strerr_die1x(100,"dnstrace: usage: dnstrace type name rootip ...");
}

static stralloc querystr;
static char ipstr[IP_FMT];
static stralloc tmp;

void printdomain(const char *d)
{
  if (!stralloc_copys(&tmp,"")) nomem();
  if (!dns_domain_todot_cat(&tmp,d)) nomem();
  buffer_put(buffer_1,tmp.s,tmp.len);
}

static struct dns_transmit tx;

static int resolve(char *q,char qtype[2],const struct ip_address * ip)
{
  struct taia start;
  struct taia stamp;
  struct taia deadline;
  struct ip_address iplocal = IP_ADDRESS_INIT;
  iopause_fd x[1];
  int r;

  taia_now(&start);

  iplocal = *ip;
  ip_make_zero(&iplocal);
  if (dns_transmit_start(&tx,ip,1U,53,0,q,qtype,&iplocal) == -1) return -1;

  for (;;) {
    taia_now(&stamp);
    taia_uint(&deadline,120);
    taia_add(&deadline,&deadline,&stamp);
    dns_transmit_io(&tx,x,&deadline);
    iopause(x,1,&deadline,&stamp);
    r = dns_transmit_get(&tx,x,&stamp);
    if (r == -1) return -1;
    if (r == 1) break;
  }

  taia_now(&stamp);
  taia_sub(&stamp,&stamp,&start);
  taia_uint(&deadline,1);
  if (taia_less(&deadline,&stamp)) {
    buffer_put(buffer_1,querystr.s,querystr.len);
    buffer_puts(buffer_1,"ALERT:took more than 1 second\n");
  }

  return 0;
}

struct address {
  char *owner;
  struct ip_address ip;
} ;

GEN_ALLOC_typedef(address_alloc,struct address,s,len,a)
GEN_ALLOC_readyplus(address_alloc,struct address,s,len,a,i,n,x,30,address_alloc_readyplus)
GEN_ALLOC_append(address_alloc,struct address,s,len,a,i,n,x,30,address_alloc_readyplus,address_alloc_append)

static address_alloc address;

struct ns {
  char *owner;
  char *ns;
} ;

GEN_ALLOC_typedef(ns_alloc,struct ns,s,len,a)
GEN_ALLOC_readyplus(ns_alloc,struct ns,s,len,a,i,n,x,30,ns_alloc_readyplus)
GEN_ALLOC_append(ns_alloc,struct ns,s,len,a,i,n,x,30,ns_alloc_readyplus,ns_alloc_append)

static ns_alloc ns;

struct query {
  char *owner;
  char type[2];
} ;

GEN_ALLOC_typedef(query_alloc,struct query,s,len,a)
GEN_ALLOC_readyplus(query_alloc,struct query,s,len,a,i,n,x,30,query_alloc_readyplus)
GEN_ALLOC_append(query_alloc,struct query,s,len,a,i,n,x,30,query_alloc_readyplus,query_alloc_append)

static query_alloc query;

struct qt {
  char *owner;
  char type[2];
  char *control;
  struct ip_address ip;
} ;

GEN_ALLOC_typedef(qt_alloc,struct qt,s,len,a)
GEN_ALLOC_readyplus(qt_alloc,struct qt,s,len,a,i,n,x,30,qt_alloc_readyplus)
GEN_ALLOC_append(qt_alloc,struct qt,s,len,a,i,n,x,30,qt_alloc_readyplus,qt_alloc_append)

static qt_alloc qt;

static void qt_add(const char *q,const char type[2],const char *control,const struct ip_address * ip)
{
  struct qt x;
  unsigned int i;

  if (!*q) return; /* don't ask the roots about our artificial . host */

  for (i = 0;i < qt.len;++i)
    if (dns_domain_equal(qt.s[i].owner,q))
      if (dns_domain_equal(qt.s[i].control,control))
        if (byte_equal(qt.s[i].type,2,type))
	  if (ip_equals(&qt.s[i].ip,ip))
	    return;

  byte_zero(&x,sizeof x);
  if (!dns_domain_copy(&x.owner,q)) nomem();
  if (!dns_domain_copy(&x.control,control)) nomem();
  byte_copy(x.type,2,type);
  x.ip = *ip;
  if (!qt_alloc_append(&qt,&x)) nomem();
}

static void query_add(const char *owner,const char type[2])
{
  struct query x;
  unsigned int i;
  unsigned int j;

  for (i = 0;i < query.len;++i)
    if (dns_domain_equal(query.s[i].owner,owner))
      if (byte_equal(query.s[i].type,2,type))
	return;

  byte_zero(&x,sizeof x);
  if (!dns_domain_copy(&x.owner,owner)) nomem();
  byte_copy(x.type,2,type);
  if (!query_alloc_append(&query,&x)) nomem();
  
  for (i = 0;i < ns.len;++i)
    if (dns_domain_suffix(owner,ns.s[i].owner))
      for (j = 0;j < address.len;++j)
	if (dns_domain_equal(ns.s[i].ns,address.s[j].owner))
	  qt_add(owner,type,ns.s[i].owner,&address.s[j].ip);
}

static void ns_add(const char *owner,const char *server)
{
  struct ns x;
  unsigned int i;
  unsigned int j;

  buffer_put(buffer_1,querystr.s,querystr.len);
  buffer_puts(buffer_1,"NS:");
  printdomain(owner);
  buffer_puts(buffer_1,":");
  printdomain(server);
  buffer_puts(buffer_1,"\n");

  for (i = 0;i < ns.len;++i)
    if (dns_domain_equal(ns.s[i].owner,owner))
      if (dns_domain_equal(ns.s[i].ns,server))
	return;

  query_add(server,DNS_T_A);

  byte_zero(&x,sizeof x);
  if (!dns_domain_copy(&x.owner,owner)) nomem();
  if (!dns_domain_copy(&x.ns,server)) nomem();
  if (!ns_alloc_append(&ns,&x)) nomem();

  for (i = 0;i < query.len;++i)
    if (dns_domain_suffix(query.s[i].owner,owner))
      for (j = 0;j < address.len;++j)
	if (dns_domain_equal(server,address.s[j].owner))
	  qt_add(query.s[i].owner,query.s[i].type,owner,&address.s[j].ip);
}

static void address_add(const char *owner,const struct ip_address *ip)
{
  struct address x;
  unsigned int i;
  unsigned int j;

  buffer_put(buffer_1,querystr.s,querystr.len);
  buffer_puts(buffer_1,"A:");
  printdomain(owner);
  buffer_puts(buffer_1,":");
  buffer_put(buffer_1,ipstr,ip_fmt(ipstr,ip,':'));
  buffer_puts(buffer_1,"\n");

  for (i = 0;i < address.len;++i)
    if (dns_domain_equal(address.s[i].owner,owner))
      if (ip_equals(&address.s[i].ip,ip))
	return;

  byte_zero(&x,sizeof x);
  if (!dns_domain_copy(&x.owner,owner)) nomem();
  x.ip = *ip;
  if (!address_alloc_append(&address,&x)) nomem();

  for (i = 0;i < ns.len;++i)
    if (dns_domain_equal(ns.s[i].ns,owner))
      for (j = 0;j < query.len;++j)
	if (dns_domain_suffix(query.s[j].owner,ns.s[i].owner))
	  qt_add(query.s[j].owner,query.s[j].type,ns.s[i].owner,ip);
}

static char seed[128];

static char *t1;
static char *t2;
static char *referral;
static char *cname;

static int typematch(const char rtype[2],const char qtype[2])
{
  return byte_equal(qtype,2,rtype);
}

void parsepacket(const char *buf,unsigned int len,const char *d,const char dtype[2],const char *control)
{
  char misc[20];
  char header[HEADER_SIZE];
  unsigned int pos;
  uint16 numanswers;
  unsigned int posanswers;
  uint16 numauthority;
  unsigned int posauthority;
  uint16 numglue;
  unsigned int posglue;
  uint16 datalen;
  unsigned int rcode;
  int flagout;
  int flagcname;
  int flagreferral;
  int flagsoa;
  int j;
  const char *x;
  struct ip_address a;

  pos = dns_packet_copy(buf,len,0,header,HEADER_SIZE); if (!pos) goto DIE;
  pos = dns_packet_skipname(buf,len,pos); if (!pos) goto DIE;
  pos += 4;

  uint16_unpack_big(header + HEADER_ANSWER,&numanswers);
  uint16_unpack_big(header + HEADER_AUTHORITY,&numauthority);
  uint16_unpack_big(header + HEADER_ADDITIONAL,&numglue);

  rcode = header[3] & 15;
  if (rcode && (rcode != 3)) { errno = error_proto; goto DIE; } /* impossible */

  flagout = 0;
  flagcname = 0;
  flagreferral = 0;
  flagsoa = 0;
  posanswers = pos;
  for (j = 0;j < numanswers;++j) {
    char rrfixed[RRFIXED_SIZE];
    pos = dns_packet_getname(buf,len,pos,&t1); if (!pos) goto DIE;
    pos = dns_packet_copy(buf,len,pos,rrfixed,RRFIXED_SIZE); if (!pos) goto DIE;
    if (dns_domain_equal(t1,d))
      if (byte_equal(rrfixed + RRFIXED_CLASS,2,DNS_C_IN)) {
	if (typematch(rrfixed + RRFIXED_TYPE,dtype))
	  flagout = 1;
	else if (typematch(rrfixed + RRFIXED_TYPE,DNS_T_CNAME)) {
          if (!dns_packet_getname(buf,len,pos,&cname)) goto DIE;
          flagcname = 1;
	}
      }
    uint16_unpack_big(rrfixed + RRFIXED_DATALEN,&datalen);
    pos += datalen;
  }
  posauthority = pos;
  for (j = 0;j < numauthority;++j) {
    char rrfixed[RRFIXED_SIZE];
    pos = dns_packet_getname(buf,len,pos,&t1); if (!pos) goto DIE;
    pos = dns_packet_copy(buf,len,pos,rrfixed,RRFIXED_SIZE); if (!pos) goto DIE;
    if (typematch(rrfixed + RRFIXED_TYPE,DNS_T_SOA))
      flagsoa = 1;
    else if (typematch(rrfixed + RRFIXED_TYPE,DNS_T_NS)) {
      flagreferral = 1;
      if (!dns_domain_copy(&referral,t1)) goto DIE;
    }
    uint16_unpack_big(rrfixed + RRFIXED_DATALEN,&datalen);
    pos += datalen;
  }
  posglue = pos;

  if (!flagcname && !rcode && !flagout && flagreferral && !flagsoa)
    if (dns_domain_equal(referral,control) || !dns_domain_suffix(referral,control)) {
      buffer_put(buffer_1,querystr.s,querystr.len);
      buffer_puts(buffer_1,"ALERT:lame server; refers to ");
      printdomain(referral);
      buffer_puts(buffer_1,"\n");
      return;
    }

  pos = posanswers;
  for (j = 0;j < numanswers + numauthority + numglue;++j) {
    char rrfixed[RRFIXED_SIZE];
    pos = dns_packet_getname(buf,len,pos,&t1); if (!pos) goto DIE;
    pos = dns_packet_copy(buf,len,pos,rrfixed,RRFIXED_SIZE); if (!pos) goto DIE;
    uint16_unpack_big(rrfixed + RRFIXED_DATALEN,&datalen);
    if (dns_domain_suffix(t1,control))
      if (byte_equal(rrfixed + RRFIXED_CLASS,2,DNS_C_IN)) {
        if (typematch(rrfixed + RRFIXED_TYPE,DNS_T_NS)) {
	  if (!dns_packet_getname(buf,len,pos,&t2)) goto DIE;
	  ns_add(t1,t2);
        }
        else if (typematch(rrfixed + RRFIXED_TYPE,DNS_T_A) && datalen == 4) {
	  if (!dns_packet_copy(buf,len,pos,misc,4)) goto DIE;
	  ip_make4(&a,misc);
	  address_add(t1,&a);
        }
      }
    pos += datalen;
  }


  if (flagcname) {
    query_add(cname,dtype);
    buffer_put(buffer_1,querystr.s,querystr.len);
    buffer_puts(buffer_1,"CNAME:");
    printdomain(cname);
    buffer_puts(buffer_1,"\n");
    return;
  }
  if (rcode == 3) {
    buffer_put(buffer_1,querystr.s,querystr.len);
    buffer_puts(buffer_1,"NXDOMAIN\n");
    return;
  }
  if (flagout || flagsoa || !flagreferral) {
    if (!flagout) {
      buffer_put(buffer_1,querystr.s,querystr.len);
      buffer_puts(buffer_1,"NODATA\n");
      return;
    }
    pos = posanswers;
    for (j = 0;j < numanswers + numauthority + numglue;++j) {
      pos = printrecord(&tmp,buf,len,pos,d,dtype,j >= numanswers + numauthority);
      if (!pos) goto DIE;
      if (tmp.len) {
        buffer_put(buffer_1,querystr.s,querystr.len);
        buffer_puts(buffer_1,"answer:");
        buffer_put(buffer_1,tmp.s,tmp.len); /* includes \n */
      }
    }
    return;
  }

  if (!dns_domain_suffix(d,referral)) goto DIE;
  buffer_put(buffer_1,querystr.s,querystr.len);
  buffer_puts(buffer_1,"see:");
  printdomain(referral);
  buffer_puts(buffer_1,"\n");
  return;

  DIE:
  x = error_str(errno);
  buffer_put(buffer_1,querystr.s,querystr.len);
  buffer_puts(buffer_1,"ALERT:unable to parse response packet; ");
  buffer_puts(buffer_1,x);
  buffer_puts(buffer_1,"\n");
}

int main(int argc,char **argv)
{
  static stralloc out;
  static stralloc fqdn;
  static stralloc udn;
  static char *q;
  char *control;
  char type[2];
  struct ip_address ip[16];
  char ddbuf[4];
  unsigned int i, j;
  uint16 u16;

  dns_random_init(seed);

  if (!stralloc_copys(&querystr,"0:.:.:start:")) nomem();

  if (!address_alloc_readyplus(&address,1)) nomem();
  if (!query_alloc_readyplus(&query,1)) nomem();
  if (!ns_alloc_readyplus(&ns,1)) nomem();
  if (!qt_alloc_readyplus(&qt,1)) nomem();

  (void)argc;
  if (!*argv) usage();
  if (!*++argv) usage();
  if (!parsetype(*argv,type)) usage();

  if (!*++argv) usage();
  if (!dns_domain_fromdot(&q,*argv,str_len(*argv))) nomem();

  query_add(q,type);
  ns_add("","");

  while (*++argv) {
    if (!stralloc_copys(&udn,*argv)) nomem();
    if (dns_ip_qualify(&out,&fqdn,&udn) == -1) nomem(); /* XXX */
    for (i = 0;i + sizeof(struct ip_address) <= out.len;i += sizeof(struct ip_address))
      address_add("",out.s + i);
  }

  for (j = 0;j < 16;++j) ip_make_unassigned(ip + j);

  for (i = 0;i < qt.len;++i) {
    if (!dns_domain_copy(&q,qt.s[i].owner)) nomem();
    control = qt.s[i].control;
    if (!dns_domain_suffix(q,control)) continue;
    byte_copy(type,2,qt.s[i].type);
    ip[0] = qt.s[i].ip;

    if (!stralloc_copys(&querystr,"")) nomem();
    uint16_unpack_big(type,&u16);
    if (!stralloc_catulong0(&querystr,u16,0)) nomem();
    if (!stralloc_cats(&querystr,":")) nomem();
    if (!dns_domain_todot_cat(&querystr,q)) nomem();
    if (!stralloc_cats(&querystr,":")) nomem();
    if (!dns_domain_todot_cat(&querystr,control)) nomem();
    if (!stralloc_cats(&querystr,":")) nomem();
    if (!stralloc_catb(&querystr,ipstr,ip_fmt(ipstr,ip,':'))) nomem();
    if (!stralloc_cats(&querystr,":")) nomem();

    buffer_put(buffer_1,querystr.s,querystr.len);
    buffer_puts(buffer_1,"tx\n");
    buffer_flush(buffer_1);

    if (resolve(q,type,ip) == -1) {
      const char *x = error_str(errno);
      buffer_put(buffer_1,querystr.s,querystr.len);
      buffer_puts(buffer_1,"ALERT:query failed; ");
      buffer_puts(buffer_1,x);
      buffer_puts(buffer_1,"\n");
    }
    else
      parsepacket(tx.packet,tx.packetlen,q,type,control);

    if (dns_domain_equal(q,"\011localhost\0")) {
      struct ip_address a;

      buffer_put(buffer_1,querystr.s,querystr.len);
      buffer_puts(buffer_1,"ALERT:some caches do not handle localhost internally\n");
      ip_make_loopback4(&a);
      address_add(q,&a);
    }
    if (dd4(q,"",ddbuf) == 4) {
      struct ip_address a;

      buffer_put(buffer_1,querystr.s,querystr.len);
      buffer_puts(buffer_1,"ALERT:some caches do not handle IP addresses internally\n");
      ip_make4(&a,ddbuf);
      address_add(q,&a);
    }

    buffer_flush(buffer_1);
  }

  return 0;
}
