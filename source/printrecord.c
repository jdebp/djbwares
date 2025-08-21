#include "uint16.h"
#include "uint32.h"
#include "error.h"
#include "byte.h"
#include "dns_constants.h"
#include "dns_packet.h"
#include "dns_domain.h"
#include "ip.h"
#include "ip4.h"
#include "ip6.h"
#include "printrecord.h"

static char *d;

unsigned int printrecord_cat(stralloc *out,const char *buf,unsigned int len,unsigned int pos,const char *q,const char qtype[2],int isglue)
{
  const char *x;
  char rrfixed[RRFIXED_SIZE];
  char misc[20];
  uint16 datalen;
  uint16 u16;
  uint32 u32;
  unsigned int newpos;
  int i;
  unsigned char ch;

  pos = dns_packet_getname(buf,len,pos,&d); if (!pos) return 0;
  pos = dns_packet_copy(buf,len,pos,rrfixed,RRFIXED_SIZE); if (!pos) return 0;
  uint16_unpack_big(rrfixed + RRFIXED_DATALEN,&datalen);
  newpos = pos + datalen;

  if (q) {
    if (!dns_domain_equal(d,q))
      return newpos;
    if (byte_diff(qtype,2,rrfixed + RRFIXED_TYPE) && byte_diff(qtype,2,DNS_T_ANY))
      return newpos;
  }

  if (!dns_domain_todot_cat(out,d)) return 0;
  if (!stralloc_cats(out," ")) return 0;

  if (isglue && byte_equal(rrfixed + RRFIXED_TYPE,2,DNS_T_OPT)) {
    uint16_unpack_big(rrfixed + RRFIXED_CLASS,&u16);
    if (!stralloc_catulong0(out,u16,0)) return 0;
    if (!stralloc_cats(out," ")) return 0;
    uint32_unpack_big(rrfixed + RRFIXED_TTL,&u32);
    if (!stralloc_catxlong0(out,u32,0)) return 0;
  } else {
    uint32_unpack_big(rrfixed + RRFIXED_TTL,&u32);
    if (!stralloc_catulong0(out,u32,0)) return 0;
    if (byte_diff(rrfixed + RRFIXED_CLASS,2,DNS_C_IN)) {
      if (!stralloc_cats(out," weird class\n")) return 0;
      return newpos;
    }
  }

  x = 0;
  if (byte_equal(rrfixed + RRFIXED_TYPE,2,DNS_T_NS)) x = " NS ";
  if (byte_equal(rrfixed + RRFIXED_TYPE,2,DNS_T_PTR)) x = " PTR ";
  if (byte_equal(rrfixed + RRFIXED_TYPE,2,DNS_T_CNAME)) x = " CNAME ";
  if (x) {
    pos = dns_packet_getname(buf,len,pos,&d); if (!pos) return 0;
    if (!stralloc_cats(out,x)) return 0;
    if (!dns_domain_todot_cat(out,d)) return 0;
  }
  else if (byte_equal(rrfixed + RRFIXED_TYPE,2,DNS_T_HINFO)) {
    if (!stralloc_cats(out," HINFO ")) return 0;
    for (i = 0;i < 2;++i) {
      pos = dns_packet_copy(buf,len,pos,misc,1); if (!pos) return 0;
      u16 = misc[0];
      while (u16) {
	--u16;
	pos = dns_packet_copy(buf,len,pos,misc,1); if (!pos) return 0;
	if ((misc[0] >= 33) && (misc[0] <= 126) && (misc[0] != '\\')) {
	  if (!stralloc_catb(out,misc,1)) return 0;
	}
	else {
	  ch = misc[0];
	  misc[3] = '0' + (7 & ch); ch >>= 3;
	  misc[2] = '0' + (7 & ch); ch >>= 3;
	  misc[1] = '0' + (7 & ch);
	  misc[0] = '\\';
	  if (!stralloc_catb(out,misc,4)) return 0;
	}
      }
    }
  }
  else if (byte_equal(rrfixed + RRFIXED_TYPE,2,DNS_T_MX)) {
    if (!stralloc_cats(out," MX ")) return 0;
    pos = dns_packet_copy(buf,len,pos,misc,2); if (!pos) return 0;
    pos = dns_packet_getname(buf,len,pos,&d); if (!pos) return 0;
    uint16_unpack_big(misc,&u16);
    if (!stralloc_catulong0(out,u16,0)) return 0;
    if (!stralloc_cats(out," ")) return 0;
    if (!dns_domain_todot_cat(out,d)) return 0;
  }
  else if (byte_equal(rrfixed + RRFIXED_TYPE,2,DNS_T_SRV)) {
    if (!stralloc_cats(out," SRV ")) return 0;
    pos = dns_packet_copy(buf,len,pos,misc,6); if (!pos) return 0;
    pos = dns_packet_getname(buf,len,pos,&d); if (!pos) return 0;
    uint16_unpack_big(misc,&u16);
    if (!stralloc_catulong0(out,u16,0)) return 0;
    if (!stralloc_cats(out," ")) return 0;
    uint16_unpack_big(misc + 2,&u16);
    if (!stralloc_catulong0(out,u16,0)) return 0;
    if (!stralloc_cats(out," ")) return 0;
    uint16_unpack_big(misc + 4,&u16);
    if (!stralloc_catulong0(out,u16,0)) return 0;
    if (!stralloc_cats(out," ")) return 0;
    if (!dns_domain_todot_cat(out,d)) return 0;
  }
  else if (byte_equal(rrfixed + RRFIXED_TYPE,2,DNS_T_SOA)) {
    if (!stralloc_cats(out," SOA ")) return 0;
    pos = dns_packet_getname(buf,len,pos,&d); if (!pos) return 0;
    if (!dns_domain_todot_cat(out,d)) return 0;
    if (!stralloc_cats(out," ")) return 0;
    pos = dns_packet_getname(buf,len,pos,&d); if (!pos) return 0;
    if (!dns_domain_todot_cat(out,d)) return 0;
    pos = dns_packet_copy(buf,len,pos,misc,20); if (!pos) return 0;
    for (i = 0;i < 5;++i) {
      if (!stralloc_cats(out," ")) return 0;
      uint32_unpack_big(misc + 4 * i,&u32);
      if (!stralloc_catulong0(out,u32,0)) return 0;
    }
  }
  else if (byte_equal(rrfixed + RRFIXED_TYPE,2,DNS_T_A)) {
    char ipstr[IP4_FMT];

    if (datalen != IP4_LEN) { errno = error_proto; return 0; }
    if (!stralloc_cats(out," A ")) return 0;
    pos = dns_packet_copy(buf,len,pos,misc,IP4_LEN); if (!pos) return 0;
    if (!stralloc_catb(out,ipstr,ip4_fmt(ipstr,misc))) return 0;
  }
  else if (byte_equal(rrfixed + RRFIXED_TYPE,2,DNS_T_AAAA)) {
    char ipstr[IP6_FMT];

    if (datalen != IP6_SANS_SCOPE_LEN) { errno = error_proto; return 0; }
    if (!stralloc_cats(out," AAAA ")) return 0;
    pos = dns_packet_copy(buf,len,pos,misc,IP6_SANS_SCOPE_LEN); if (!pos) return 0;
    if (!stralloc_catb(out,ipstr,ip6_fmt(ipstr,misc,':'))) return 0;
  }
  else if (byte_equal(rrfixed + RRFIXED_TYPE,2,DNS_T_LOC)) {
    long l;

    if (datalen != 16) { errno = error_proto; return 0; }
    if (!stralloc_cats(out," LOC ")) return 0;
    pos = dns_packet_copy(buf,len,pos,misc,16); if (!pos) return 0;
    if (!stralloc_catxlong0(out,misc[0],2)) return 0;
    if (!stralloc_cats(out," ")) return 0;
    if (!stralloc_catxlong0(out,misc[1],2)) return 0;
    if (!stralloc_cats(out," ")) return 0;
    if (!stralloc_catxlong0(out,misc[2],2)) return 0;
    if (!stralloc_cats(out," ")) return 0;
    if (!stralloc_catxlong0(out,misc[3],2)) return 0;
    if (!stralloc_cats(out," ")) return 0;
    uint32_unpack_big(misc + 4,&u32);
    l = u32 >= 0x80000000 ? (long)(u32 - 0x80000000) : (long)(u32) - (long)0x7FFFFFFF - 1;
    if (!stralloc_catlong0(out,l / 1000,0)) return 0;
    if (!stralloc_cats(out,".")) return 0;
    if (!stralloc_catlong0(out,l % 1000 + ((l < 0) ? 1000 : 0),3)) return 0;
    if (!stralloc_cats(out," ")) return 0;
    uint32_unpack_big(misc + 8,&u32);
    l = u32 >= 0x80000000 ? (long)(u32 - 0x80000000) : (long)(u32) - (long)0x7FFFFFFF - 1;
    if (!stralloc_catlong0(out,l / 1000,0)) return 0;
    if (!stralloc_cats(out,".")) return 0;
    if (!stralloc_catlong0(out,l % 1000 + ((l < 0) ? 1000 : 0),3)) return 0;
    if (!stralloc_cats(out," ")) return 0;
    uint32_unpack_big(misc + 12,&u32);
    if (u32 >= 10000000UL ? !stralloc_catulong0(out,u32 - 10000000UL,0) : !stralloc_catlong0(out,(long)u32 - 10000000L,0)) return 0;
  }
  else if (byte_equal(rrfixed + RRFIXED_TYPE,2,DNS_T_HTTPS) || byte_equal(rrfixed + RRFIXED_TYPE,2,DNS_T_SVCB)) {
    unsigned int oldpos = pos;
    if (!stralloc_cats(out,byte_equal(rrfixed + RRFIXED_TYPE,2,DNS_T_SVCB) ? " SVCB " : " HTTPS ")) return 0;
    pos = dns_packet_copy(buf,len,pos,misc,2); if (!pos) return 0;
    pos = dns_packet_getname(buf,len,pos,&d); if (!pos) return 0;
    uint16_unpack_big(misc,&u16);
    if (!stralloc_catulong0(out,u16,0)) return 0;
    if (!stralloc_cats(out," ")) return 0;
    if (!dns_domain_todot_cat(out,d)) return 0;
    if (!stralloc_cats(out," ")) return 0;
    datalen = datalen >= (pos - oldpos) ? datalen - (pos - oldpos) : 0;
    while (datalen > 0) {
      uint16 paramkey, paramlen;

      if (datalen < 4) return 0; datalen -= 4;
      pos = dns_packet_copy(buf,len,pos,misc,4); if (!pos) return 0;
      uint16_unpack_big(misc + 0,&paramkey);
      uint16_unpack_big(misc + 2,&paramlen);
      if (datalen < paramlen) return 0; datalen -= paramlen;
      if (!stralloc_catulong0(out,paramkey,0)) return 0;
      if (!stralloc_cats(out,"=")) return 0;
      while (paramlen > 0) {
        pos = dns_packet_copy(buf,len,pos,misc,1); if (!pos) return 0;
        --paramlen;
        if ((misc[0] >= 33) && (misc[0] <= 126) && (misc[0] != '\\')) {
          if (!stralloc_catb(out,misc,1)) return 0;
        }
        else {
          ch = misc[0];
          misc[3] = '0' + (7 & ch); ch >>= 3;
          misc[2] = '0' + (7 & ch); ch >>= 3;
          misc[1] = '0' + (7 & ch);
          misc[0] = '\\';
          if (!stralloc_catb(out,misc,4)) return 0;
        }
      }
      if (!stralloc_cats(out," ")) return 0;
    }
  }
  else if (byte_equal(rrfixed + RRFIXED_TYPE,2,DNS_T_OPT)) {
    if (!stralloc_cats(out," OPT ")) return 0;
  }
  else {
    if (byte_equal(rrfixed + RRFIXED_TYPE,2,DNS_T_TXT)) {
      if (!stralloc_cats(out," TXT ")) return 0;
    }
    else {
      if (!stralloc_cats(out," ")) return 0;
      uint16_unpack_big(misc,&u16);
      if (!stralloc_catulong0(out,u16,0)) return 0;
      if (!stralloc_cats(out," ")) return 0;
    }
    while (datalen--) {
      pos = dns_packet_copy(buf,len,pos,misc,1); if (!pos) return 0;
      if ((misc[0] >= 33) && (misc[0] <= 126) && (misc[0] != '\\')) {
        if (!stralloc_catb(out,misc,1)) return 0;
      }
      else {
        ch = misc[0];
        misc[3] = '0' + (7 & ch); ch >>= 3;
        misc[2] = '0' + (7 & ch); ch >>= 3;
        misc[1] = '0' + (7 & ch);
        misc[0] = '\\';
        if (!stralloc_catb(out,misc,4)) return 0;
      }
    }
  }

  if (!stralloc_cats(out,"\n")) return 0;
  if (pos != newpos) { errno = error_proto; return 0; }
  return newpos;
}

unsigned int printrecord(stralloc *out,const char *buf,unsigned int len,unsigned int pos,const char *q,const char qtype[2],int isglue)
{
  if (!stralloc_copys(out,"")) return 0;
  return printrecord_cat(out,buf,len,pos,q,qtype,isglue);
}
