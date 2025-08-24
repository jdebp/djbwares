#include "str.h"
#include "mem.h"
#include "scan.h"
#include "exit.h"
#include "stralloc.h"
#include "buffer.h"
#include "strerr.h"
#include "uint16.h"
#include "response.h"
#include "case.h"
#include "printpacket.h"
#include "parsetype.h"
#include "ip.h"
#include "ip4.h"
#include "dns_constants.h"
#include "dns_domain.h"
#include "dns_packet.h"
#include "dns_server.h"

#define FATAL "tinydns-get: fatal: "

void usage(void)
{
  strerr_die1x(100,"tinydns-get: usage: tinydns-get type name [ip]");
}
void oops(void)
{
  strerr_die2sys(111,FATAL,"unable to parse: ");
}

static struct ip_address ip;
static char type[2];
static char *q;

static stralloc out;

int main(int argc,char **argv)
{
  uint16 u16;

  (void)argc;
  if (!*argv) usage();

  if (!*++argv) usage();
  if (!parsetype(*argv,type)) usage();

  if (!*++argv) usage();
  if (!dns_domain_fromdot(&q,*argv,str_len(*argv))) oops();

  if (*++argv) {
    if (!ip_scan(*argv,&ip,':')) usage();
  }

  if (!stralloc_copys(&out,"")) oops();
  uint16_unpack_big(type,&u16);
  if (!stralloc_catulong0(&out,u16,0)) oops();
  if (!stralloc_cats(&out," ")) oops();
  if (!dns_domain_todot_cat(&out,q)) oops();
  if (!stralloc_cats(&out,":\n")) oops();

  if (!response_query(q,type,DNS_C_IN)) oops();
  response[3] &= ~128;	/* set RA=0 */
  response[2] &= ~1;  /* set RD=0 */
  response[2] |= 4; /* set AA=1 */
  case_lowerb(q,dns_domain_length(q));

  if (dns_packet_typematch(type,DNS_T_AXFR)||dns_packet_typematch(type,DNS_T_IXFR)) {
    response[3] &= ~15;
    response[3] |= 4;
  }
  else
    if (!respond(q,type,MAX_RESPONSE,&ip)) goto DONE;

  if (!printpacket_cat(&out,response,response_len)) oops();

  DONE:
  buffer_putflush(buffer_1,out.s,out.len);
  _exit(0);
}
