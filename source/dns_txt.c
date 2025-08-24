#include "stralloc.h"
#include "uint16.h"
#include "byte.h"
#include "dns_transmit.h"
#include "dns_resolve.h"
#include "dns_domain.h"
#include "dns_packet.h"

static int dns_txt_packet(stralloc *out,const char *buf,unsigned int len)
{
  unsigned int pos;
  char header[HEADER_SIZE];
  uint16 numanswers;
  uint16 datalen;
  char ch;
  unsigned int txtlen;
  int i;

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
    if (dns_packet_rrtypematch(rrfixed,DNS_T_TXT))
      if (dns_packet_rrinternetclass(rrfixed)) {
	if (pos + datalen > len) return -1;
	txtlen = 0;
	for (i = 0;i < datalen;++i) {
	  ch = buf[pos + i];
	  if (!txtlen)
	    txtlen = (unsigned char) ch;
	  else {
	    --txtlen;
	    if (ch < 32) ch = '?';
	    if (ch > 126) ch = '?';
	    if (!stralloc_append(out,&ch)) return -1;
	  }
	}
      }
    pos += datalen;
  }

  return 0;
}

static char *q = 0;

int dns_txt(stralloc *out,const stralloc *fqdn)
{
  if (!dns_domain_fromdot(&q,fqdn->s,fqdn->len)) return -1;
  if (dns_resolve(q,DNS_T_TXT) == -1) return -1;
  if (dns_txt_packet(out,dns_resolve_tx.packet,dns_resolve_tx.packetlen) == -1) return -1;
  dns_transmit_free(&dns_resolve_tx);
  dns_domain_free(&q);
  return 0;
}
