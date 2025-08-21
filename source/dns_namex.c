#include "stralloc.h"
#include "uint16.h"
#include "byte.h"
#include "dns_nd.h"
#include "dns_transmit.h"
#include "dns_resolve.h"
#include "dns_packet.h"
#include "dns_domain.h"
#include "ip.h"

static char *q = 0;

static int dns_name_packet_multi(stralloc *out,const char *buf,unsigned int len)
{
  unsigned int pos;
  char header[HEADER_SIZE];
  uint16 numanswers;
  uint16 datalen;

  if (!stralloc_copys(out,"")) return -1;

  pos = dns_packet_copy(buf,len,0,header,HEADER_SIZE); if (!pos) return -1;
  uint16_unpack_big(header + HEADER_ANSWER,&numanswers);
  pos = dns_packet_skipname(buf,len,pos); if (!pos) return -1;
  pos += 4;

  while (numanswers--) {
    char rrfixed[RRFIXED_SIZE];
    pos = dns_packet_skipname(buf,len,pos); if (!pos) return -1;
    pos = dns_packet_copy(buf,len,pos,rrfixed,RRFIXED_SIZE); if (!pos) return -1;
    uint16_unpack_big(rrfixed + RRFIXED_DATALEN,&datalen);
    if (byte_equal(rrfixed + RRFIXED_TYPE,2,DNS_T_PTR))
      if (byte_equal(rrfixed + RRFIXED_CLASS,2,DNS_C_IN)) {
	if (!dns_packet_getname(buf,len,pos,&q)) return -1;
	if (!dns_domain_todot_cat(out,q)) return -1;
	if (!stralloc_cats(out, " ")) return -1 ; 
      }
    pos += datalen;
  }

  return 0;
}

int dns_name_multi(stralloc *out,const struct ip_address * ip)
{
  char name[DNS_NAME_DOMAIN];

  dns_name_domain(name,ip);
  if (dns_resolve(name,DNS_T_PTR) == -1) return -1;
  if (dns_name_packet_multi(out,dns_resolve_tx.packet,dns_resolve_tx.packetlen) == -1) return -1;
  dns_transmit_free(&dns_resolve_tx);
  dns_domain_free(&q);
  return 0;
}
