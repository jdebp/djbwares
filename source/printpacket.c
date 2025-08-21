#include "uint16.h"
#include "uint32.h"
#include "error.h"
#include "byte.h"
#include "dns_constants.h"
#include "dns_packet.h"
#include "dns_domain.h"
#include "printrecord.h"
#include "printpacket.h"

static char *d;

#define X(s) do {if (!stralloc_cats(out,s)) return 0;} while(0)
#define NUM(u) do {if (!stralloc_catulong0(out,u,0)) return 0;} while(0)

static unsigned int printpacket_qtype(stralloc *out,const char type[2])
{
  if (byte_equal(type,2,DNS_T_A)) X("a");
  else if (byte_equal(type,2,DNS_T_AAAA)) X("aaaa");
  else if (byte_equal(type,2,DNS_T_TXT)) X("txt");
  else if (byte_equal(type,2,DNS_T_MX)) X("mx");
  else if (byte_equal(type,2,DNS_T_SOA)) X("soa");
  else if (byte_equal(type,2,DNS_T_CNAME)) X("cname");
  else if (byte_equal(type,2,DNS_T_PTR)) X("ptr");
  else if (byte_equal(type,2,DNS_T_SIG)) X("sig");
  else if (byte_equal(type,2,DNS_T_SRV)) X("srv");
  else if (byte_equal(type,2,DNS_T_LOC)) X("loc");
  else if (byte_equal(type,2,DNS_T_OPT)) X("opt");
  else if (byte_equal(type,2,DNS_T_HTTPS)) X("https");
  else if (byte_equal(type,2,DNS_T_SVCB)) X("svcb");
  else {
    uint16 u;

    uint16_unpack_big(type,&u);
    NUM(u);
  }
  return 1;
}

unsigned int printpacket_cat(stralloc *out,char *buf,unsigned int len)
{
  uint16 numqueries;
  uint16 numanswers;
  uint16 numauthority;
  uint16 numglue;
  unsigned int pos;
  char data[HEADER_SIZE];

  pos = dns_packet_copy(buf,len,0,data,HEADER_SIZE); if (!pos) return 0;

  uint16_unpack_big(data + HEADER_QUERY,&numqueries);
  uint16_unpack_big(data + HEADER_ANSWER,&numanswers);
  uint16_unpack_big(data + HEADER_AUTHORITY,&numauthority);
  uint16_unpack_big(data + HEADER_ADDITIONAL,&numglue);

  NUM(len);
  X(" bytes, ");
  NUM(numqueries);
  X("+");
  NUM(numanswers);
  X("+");
  NUM(numauthority);
  X("+");
  NUM(numglue);
  X(" records");

  if (data[2] & 128) X(", response");
  if (data[2] & 120) X(", weird op");
  if (data[2] & 4) X(", authoritative");
  if (data[2] & 2) X(", truncated");
  if (data[2] & 1) X(", weird rd");
  if (data[3] & 128) X(", weird ra");
  switch(data[3] & 15) {
    case 0: X(", noerror"); break;
    case 3: X(", nxdomain"); break;
    case 4: X(", notimp"); break;
    case 5: X(", refused"); break;
    default: X(", weird rcode");
  }
  if (data[3] & 112) X(", weird z");

  X("\n");

  while (numqueries) {
    --numqueries;
    X("query: ");

    pos = dns_packet_getname(buf,len,pos,&d); if (!pos) return 0;
    pos = dns_packet_copy(buf,len,pos,data,4); if (!pos) return 0;

    if (byte_diff(data + 2,2,DNS_C_IN)) {
      X("weird class");
    }
    else {
      if (!printpacket_qtype(out,data)) return 0;
      X(" ");
      if (!dns_domain_todot_cat(out,d)) return 0;
    }
    X("\n");
  }

  for (;;) {
    int isglue = 0;
    if (numanswers) { --numanswers; X("answer: "); }
    else if (numauthority) { --numauthority; X("authority: "); }
    else if (numglue) { --numglue; X("additional: "); isglue = 1; }
    else break;

    pos = printrecord_cat(out,buf,len,pos,0,0,isglue);
    if (!pos) return 0;
  }

  if (pos != len) { errno = error_proto; return 0; }
  return 1;
}
