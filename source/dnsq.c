#include "uint16.h"
#include "strerr.h"
#include "buffer.h"
#include "scan.h"
#include "str.h"
#include "byte.h"
#include "error.h"
#include "ip.h"
#include "iopause.h"
#include "printpacket.h"
#include "parsetype.h"
#include "dns_transmit.h"
#include "dns_resolve.h"
#include "dns_random.h"
#include "dns_domain.h"
#include "exit.h"

#define FATAL "dnsq: fatal: "

void usage(void)
{
  strerr_die1x(100,"dnsq: usage: dnsq type name server");
}
void oops(void)
{
  strerr_die2sys(111,FATAL,"unable to parse: ");
}

static stralloc ip;
static stralloc fqdn;

static char type[2];
static char *q;

static stralloc out;

static char seed[128];

int main(int argc,char **argv)
{
  uint16 u16;
  unsigned int server_count;
  struct ip_address server_list[16];
  unsigned int j;

  dns_random_init(seed);

  (void)argc;
  if (!*argv) usage();
  if (!*++argv) usage();
  if (!parsetype(*argv,type)) usage();

  if (!*++argv) usage();
  if (!dns_domain_fromdot(&q,*argv,str_len(*argv))) oops();

  if (!*++argv) usage();
  if (!stralloc_copys(&out,*argv)) oops();
  if (dns_ip_qualify(&ip,&fqdn,&out) == -1) oops();
  if (ip.len > sizeof server_list) ip.len = sizeof server_list;
  for (j = 0; j < sizeof server_list/sizeof *server_list; ++j)
    ip_make_unassigned(server_list + j);
  byte_copy(server_list,ip.len,ip.s);
  server_count = ip.len / sizeof *server_list;

  if (!stralloc_copys(&out,"")) oops();
  uint16_unpack_big(type,&u16);
  if (!stralloc_catulong0(&out,u16,0)) oops();
  if (!stralloc_cats(&out," ")) oops();
  if (!dns_domain_todot_cat(&out,q)) oops();
  if (!stralloc_cats(&out,":\n")) oops();

  if (dns_resolve_servers_nospecials(q,type,server_list,server_count,53,0) == -1) {
    if (!stralloc_cats(&out,error_str(errno))) oops();
    if (!stralloc_cats(&out,"\n")) oops();
  }
  else {
    if (!printpacket_cat(&out,dns_resolve_tx.packet,dns_resolve_tx.packetlen)) oops();
  }

  buffer_putflush(buffer_1,out.s,out.len);
  return 0;
}
