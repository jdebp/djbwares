#include "stralloc.h"
#include "uint16.h"
#include "byte.h"
#include "dns_sortip.h"
#include "dns_transmit.h"
#include "dns_resolve.h"
#include "dns_packet.h"
#include "dns_domain.h"
#include "ip.h"
#include "ip4.h"
#include "dd.h"

static int dns_ip_packet(stralloc *out,const char *buf,unsigned int len)
{
  unsigned int pos;
  char header[HEADER_SIZE];
  uint16 numanswers;
  uint16 datalen;

  pos = dns_packet_copy(buf,len,0,header,HEADER_SIZE); if (!pos) return -1;
  uint16_unpack_big(header + HEADER_ANSWER,&numanswers);
  pos = dns_packet_skipname(buf,len,pos); if (!pos) return -1;
  pos += 4;

  while (numanswers--) {
    char rrfixed[RRFIXED_SIZE];
    pos = dns_packet_skipname(buf,len,pos); if (!pos) return -1;
    pos = dns_packet_copy(buf,len,pos,rrfixed,RRFIXED_SIZE); if (!pos) return -1;
    uint16_unpack_big(rrfixed + RRFIXED_DATALEN,&datalen);
    if (byte_equal(rrfixed + RRFIXED_CLASS,2,DNS_C_IN)) {
      if (byte_equal(rrfixed + RRFIXED_TYPE,2,DNS_T_A)) {
	char a[IP4_LEN];
        if (sizeof a == datalen) {
	  struct ip_address ip;
	  if (!dns_packet_copy(buf,len,pos,a,sizeof a)) return -1;
	  ip_make4(&ip,a);
	  if (!stralloc_catb(out,&ip,sizeof ip)) return -1;
        }
      } else
      if (byte_equal(rrfixed + RRFIXED_TYPE,2,DNS_T_AAAA)) {
	char a[IP6_SANS_SCOPE_LEN];
        if (sizeof a == datalen) {
	  struct ip_address ip;
	  if (!dns_packet_copy(buf,len,pos,a,sizeof a)) return -1;
	  ip_make6(&ip,a,0);
	  if (!stralloc_catb(out,&ip,sizeof ip)) return -1;
        }
      }
    }
    pos += datalen;
  }

  return 0;
}

static char *q = 0;

int dns_ip4(stralloc *out,const stralloc *fqdn)
{
  struct ip_address a = IP_ADDRESS_INIT;
  unsigned int l;

  if (!stralloc_copys(out,"")) return -1;
  if ((l = ip4_scan_n(fqdn->s,fqdn->len,&a)) && l == fqdn->len) {
    if (!stralloc_catb(out,&a,sizeof a)) return -1;
    return 0;
  }
  if (!dns_domain_fromdot(&q,fqdn->s,fqdn->len)) return -1;
  if (dns_resolve(q,DNS_T_A) == -1) return -1;
  if (dns_ip_packet(out,dns_resolve_tx.packet,dns_resolve_tx.packetlen) == -1) return -1;
  dns_transmit_free(&dns_resolve_tx);
  dns_domain_free(&q);
  dns_sortip(out->s,out->len / sizeof(struct ip_address));
  return 0;
}

int dns_ip(stralloc *out,const stralloc *fqdn)
{
  struct ip_address a = IP_ADDRESS_INIT;
  unsigned int l;

  if (!stralloc_copys(out,"")) return -1;
  if ((l = ip_scan_n(fqdn->s,fqdn->len,&a,':')) && l == fqdn->len) {
    if (!stralloc_catb(out,&a,sizeof a)) return -1;
    return 0;
  }
  if (!dns_domain_fromdot(&q,fqdn->s,fqdn->len)) return -1;
  if (dns_resolve(q,DNS_T_AAAA) == -1) return -1;
  if (dns_ip_packet(out,dns_resolve_tx.packet,dns_resolve_tx.packetlen) == -1) return -1;
  dns_transmit_free(&dns_resolve_tx);
  if (dns_resolve(q,DNS_T_A) == -1) return -1;
  if (dns_ip_packet(out,dns_resolve_tx.packet,dns_resolve_tx.packetlen) == -1) return -1;
  dns_transmit_free(&dns_resolve_tx);
  dns_domain_free(&q);
  dns_sortip(out->s,out->len / sizeof(struct ip_address));
  return 0;
}
