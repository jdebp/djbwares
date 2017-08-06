#include "uint16.h"
#include "exit.h"
#include "sgetopt.h"
#include "str.h"
#include "fmt.h"
#include "scan.h"
#include "byte.h"
#include "error.h"
#include "strerr.h"
#include "alloc.h"
#include "buffer.h"
#include "printpacket.h"
#include "parsetype.h"
#include "ip4.h"
#include "ip6.h"
#include "dns.h"

#define FATAL "host: fatal: "

void nomem(void)
{
  strerr_die2x(111,FATAL,"out of memory");
}
void oops(void)
{
  strerr_die2sys(111,FATAL,"unable to parse: ");
}
void usage(void)
{
  strerr_die1x(100,"host: usage: host \
[-4 | -6] \
[-ar] \
[-t type] \
name [server]");
}

static char seed[128];

static stralloc ip;
static stralloc fqdn;
static stralloc iname;
static stralloc srv;
static stralloc out;
static stralloc rules;

static
int
doit(const char * qname,const char qtype[2],const char servers[64],int flagrecursive)
{
  uint16 u16;
  int r = 0;

  if (!stralloc_copys(&out,"")) nomem();
  uint16_unpack_big(qtype,&u16);
  if (!stralloc_catulong0(&out,u16,0)) nomem();
  if (!stralloc_cats(&out," ")) nomem();
  if (!dns_domain_todot_cat(&out,qname)) oops();
  if (!stralloc_cats(&out,":\n")) nomem();

  if (dns_resolve_servers(qname,qtype,servers,flagrecursive) == -1) {
    if (!stralloc_cats(&out,error_str(errno))) nomem();
    if (!stralloc_cats(&out,"\n")) nomem();
  } else {
    if (flagrecursive) {
      if (dns_resolve_tx.packetlen < 4) oops();
      dns_resolve_tx.packet[2] &= ~1;
      dns_resolve_tx.packet[3] &= ~128;
    }
    if (!printpacket_cat(&out,dns_resolve_tx.packet,dns_resolve_tx.packetlen)) oops();
    r = 1;
  }
  dns_transmit_free(&dns_resolve_tx);
  return r;
}

static
void
optarg_num ( unsigned long * u )
{
  unsigned int pos ;
  pos = scan_ulong(optarg,u); 
  if (0 == pos || optarg[pos])
    strerr_die3x(111,FATAL, optarg, " is not a number");
}

int
main(int argc,char **argv)
{
  unsigned long u;
  int r;
  int opt;
  int flag4 = 1;
  int flag6 = 1;
  int flagd = 0;
  int flagrecursive = 1;
  int flags = 0;
  int flagT = 0;
  int flagv = 0;
  int flagw = 0;
  int retries = 0;
  int waittime = 0;
  const char * klass = 0;
  const char * type = 0;
  const char * name = 0;
  const char * server = 0;
  char * qname = 0;
  char qtype[2];
  char servers[64];

  while ((opt = getopt(argc,argv,"46adrsTvwc:t:R:W:")) != opteof)
    switch(opt) {
      case '4': flag6 = 0; break;
      case '6': flag4 = 0; break;
      case 'a': type = "any"; break;
      case 'd': flagd = 1; break;
      case 'r': flagrecursive = 0; break;
      case 's': flags = 1; break;
      case 'T': flagT = 1; break;
      case 'v': flagv = 1; break;
      case 'w': flagw = 1; break;
      case 'c': klass = optarg; break;
      case 't': type = optarg; break;
      case 'R': optarg_num(&u); retries = u; break;
      case 'W': optarg_num(&u); waittime = u; break;
      default: usage();
    }
  argv += optind;

  name = *argv++;
  if (!name) usage();
  server = *argv;
  if (server) ++argv;
  if (*argv) usage();

  if (!flag6 && !flag4) usage();
  if (type) {
    if (!parsetype(type,qtype)) oops();
  }
  if (!qname && flag4) {
    char ip4[4];
    unsigned int l;

    l = ip4_scan(name,ip4);
    if (l && !name[l]) {
      char qbuf4[DNS_NAME4_DOMAIN];
      dns_name4_domain(qbuf4,ip4);
      qname = alloc(sizeof qbuf4);
      if (!qname) nomem();
      byte_copy(qname,sizeof qbuf4,qbuf4);
      if (!type) byte_copy(qtype,2,DNS_T_PTR);
    }
  }
  if (!qname && flag6) {
    char ip6[16];
    unsigned int l;

    l = ip6_scan(name,ip6,':');
    if (l && !name[l]) {
      char qbuf6[DNS_NAME6_DOMAIN];
      dns_name6_domain(qbuf6,ip6);
      qname = alloc(sizeof qbuf6);
      if (!qname) nomem();
      byte_copy(qname,sizeof qbuf6,qbuf6);
      if (!type) byte_copy(qtype,2,DNS_T_PTR);
    }
  } 

  dns_random_init(seed);

  if (server) {
    if (!stralloc_copys(&srv,server)) nomem();
    if (dns_ip4_qualify(&ip,&fqdn,&srv) == -1) oops();
    if (ip.len >= 64) ip.len = 64;
    byte_zero(servers,64);
    byte_copy(servers,ip.len,ip.s);
  } else {
    if (dns_resolvconfip(servers) == -1) oops();
  }

  if (qname) {
    r = doit(qname,qtype,servers,flagrecursive);
    dns_domain_free(&qname);
  } else {
    unsigned int plus,fqdnlen;

    if (!type) {
      if (flag4) 
	byte_copy(qtype,2,DNS_T_A);
      else if (flag6) 
	byte_copy(qtype,2,DNS_T_AAAA);
      else
	usage();
    }
    if (dns_resolvconfrewrite(&rules) == -1) oops();
    if (!stralloc_copys(&iname,name)) nomem();
    if (dns_qualify_rules(&fqdn,&iname,&rules) == -1) oops();

    fqdnlen = fqdn.len;
    plus = byte_chr(fqdn.s,fqdnlen,'+');
    if (plus >= fqdnlen) {
      if (!dns_domain_fromdot(&qname,fqdn.s,fqdn.len)) oops();
      r = doit(qname,qtype,servers,flagrecursive);
      dns_domain_free(&qname);
    } else {
      unsigned int i;

      i = plus + 1;
      for (;;) {
	unsigned int j;

	j = byte_chr(fqdn.s + i,fqdnlen - i,'+');
	byte_copy(fqdn.s + plus,j,fqdn.s + i);
	fqdn.len = plus + j;
	if (!dns_domain_fromdot(&qname,fqdn.s,fqdn.len)) oops();
	r = doit(qname,qtype,servers,flagrecursive);
	dns_domain_free(&qname);
	if (r) break;
	i += j;
	if (i >= fqdnlen) break;
	++i;
      }
    }
  }

  buffer_putflush(buffer_1,out.s,out.len);
  _exit(!r);
}
