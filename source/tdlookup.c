#include <unistd.h>
#include "uint16.h"
#include "open.h"
#include "tai.h"
#include "cdb.h"
#include "byte.h"
#include "case.h"
#include "dns_domain.h"
#include "dns_packet.h"
#include "dns_server.h"
#include "dns_random.h"
#include "dns_constants.h"
#include "seek.h"
#include "response.h"
#include "ip.h"
#include "ip4.h"

static int want(const char *owner,const char type[2])
{
  unsigned int pos;
  static char *d;

  pos = dns_packet_skipname(response,response_len,HEADER_SIZE); if (!pos) return 0;
  pos += 4;

  while (pos < response_len) {
    char rrfixed[RRFIXED_SIZE];
    uint16 datalen;
    pos = dns_packet_getname(response,response_len,pos,&d); if (!pos) return 0;
    pos = dns_packet_copy(response,response_len,pos,rrfixed,RRFIXED_SIZE); if (!pos) return 0;
    if (dns_domain_equal(d,owner))
      if (byte_equal(rrfixed + RRFIXED_TYPE,2,type))
        return 0;
    uint16_unpack_big(rrfixed + RRFIXED_DATALEN,&datalen);
    pos += datalen;
  }
  return 1;
}

static char *d1;

static char clientloc[2];
static struct tai now;
static struct cdb c;

static char data[32767];
static uint32 dlen;
static unsigned int dpos;
static char type[2];
static uint32 ttl;

static int find(const char *d,int flagwild)
{
  int r;
  char ch;
  struct tai cutoff;
  char ttd[8];
  char ttlstr[4];
  char recordloc[2];
  double newttl;

  for (;;) {
    r = cdb_findnext(&c,d,dns_domain_length(d));
    if (r <= 0) return r;
    dlen = cdb_datalen(&c);
    if (dlen > sizeof data) return -1;
    if (cdb_read(&c,data,dlen,cdb_datapos(&c)) == -1) return -1;
    dpos = dns_packet_copy(data,dlen,0,type,2); if (!dpos) return -1;
    dpos = dns_packet_copy(data,dlen,dpos,&ch,1); if (!dpos) return -1;
    if ((ch == '=' + 1) || (ch == '*' + 1)) {
      --ch;
      dpos = dns_packet_copy(data,dlen,dpos,recordloc,2); if (!dpos) return -1;
      if (byte_diff(recordloc,2,clientloc)) continue;
    }
    if (flagwild != (ch == '*')) continue;
    dpos = dns_packet_copy(data,dlen,dpos,ttlstr,4); if (!dpos) return -1;
    uint32_unpack_big(ttlstr,&ttl);
    dpos = dns_packet_copy(data,dlen,dpos,ttd,8); if (!dpos) return -1;
    if (byte_diff(ttd,8,"\0\0\0\0\0\0\0\0")) {
      tai_unpack(ttd,&cutoff);
      if (ttl == 0) {
	if (tai_less(&cutoff,&now)) continue;
	tai_sub(&cutoff,&cutoff,&now);
	newttl = tai_approx(&cutoff);
	if (newttl <= 2.0) newttl = 2.0;
	if (newttl >= 3600.0) newttl = 3600.0;
	ttl = newttl;
      }
      else
	if (!tai_less(&cutoff,&now)) continue;
    }
    return 1;
  }
}

static int dobytes(unsigned int len)
{
  char buf[20];
  if (len > 20) return 0;
  dpos = dns_packet_copy(data,dlen,dpos,buf,len);
  if (!dpos) return 0;
  return response_addbytes(buf,len);
}

static int doname(void)
{
  dpos = dns_packet_getname(data,dlen,dpos,&d1);
  if (!dpos) return 0;
  return response_addname(d1);
}

static int doit1(char **pqname,const char qtype[2],unsigned int max)
{
  unsigned int bpos;
  unsigned int anpos;
  unsigned int aupos;
  unsigned int arpos;
  const char *q;
  const char *control;
  const char *wild;
  int flaggavesoa;
  int flagfound;
  int r;
  int flagns;
  int flagauthoritative;
  char x[20];
  uint16 datalen;
  char addr4[8][IP4_LEN];
  char addr6[8][IP6_SANS_SCOPE_LEN];
  int addr4num, addr6num;
  uint32 addr4ttl, addr6ttl;
  int i;
  int loop = 0 ;

RESTART:
  if (loop++ >= 100) return 0 ;

  q = *pqname ;

  anpos = response_len;

  control = q;
  for (;;) {
    flagns = 0;
    flagauthoritative = 0;
    cdb_findstart(&c);
    while ((r = find(control,0))) {
      if (r == -1) return 0;
      if (byte_equal(type,2,DNS_T_SOA)) flagauthoritative = 1;
      if (byte_equal(type,2,DNS_T_NS)) flagns = 1;
    }
    if (flagns) break;
    if (!*control) { /* q is not within our bailiwick */
      if (loop <= 1)
        return 0 ;
      else {
        response[2] &= ~4;  /* set AA=0 */
        goto DONE; /* The administrator has issued contradictory instructions */
      }
    }
    control += *control;
    control += 1;
  }

  if (!flagauthoritative) {
    response[2] &= ~4;  /* set AA=0 */
    goto AUTHORITY; /* q is in a child zone */
  }


  flaggavesoa = 0;
  flagfound = 0;
  wild = q;

  for (;;) {
    addr4num = addr6num = 0;
    addr4ttl = addr6ttl = 0;
    cdb_findstart(&c);
    while ((r = find(wild,wild != q))) {
      if (r == -1) return 0;
      flagfound = 1;
      if (byte_diff(type,2,DNS_T_CNAME) && byte_equal(qtype,2,DNS_T_ANY)) continue;
      if (flaggavesoa && byte_equal(type,2,DNS_T_SOA)) continue;
      if (byte_diff(type,2,qtype) && byte_diff(type,2,DNS_T_CNAME)) continue;
      if (byte_equal(type,2,DNS_T_A) && (dlen - dpos == IP4_LEN)) {
	addr4ttl = ttl;
	i = dns_random(addr4num + 1);
	if (i < 8) {
	  if ((i < addr4num) && (addr4num < 8))
	    byte_copy(addr4[addr4num],IP4_LEN,addr4[i]);
	  byte_copy(addr4[i],IP4_LEN,data + dpos);
	}
	if (addr4num < 1000000) ++addr4num;
	continue;
      }
      if (byte_equal(type,2,DNS_T_AAAA) && (dlen - dpos == IP6_SANS_SCOPE_LEN)) {
	addr6ttl = ttl;
	i = dns_random(addr6num + 1);
	if (i < 8) {
	  if ((i < addr6num) && (addr6num < 8))
	    byte_copy(addr6[addr6num],IP6_SANS_SCOPE_LEN,addr6[i]);
	  byte_copy(addr6[i],IP6_SANS_SCOPE_LEN,data + dpos);
	}
	if (addr6num < 1000000) ++addr6num;
	continue;
      }
      if (!response_rstart(q,type,ttl)) return 0;
      if (byte_equal(type,2,DNS_T_NS) || byte_equal(type,2,DNS_T_PTR)) {
	if (!doname()) return 0;
      }
      else if (byte_equal(type,2,DNS_T_CNAME)) {
	if (!doname()) return 0;
        if (byte_diff(type,2,qtype)) {
	  response_rfinish(RESPONSE_ANSWER);
          case_lowerb(d1,dns_domain_length(d1));
	  if (!dns_domain_copy(pqname,d1)) return 0 ;
	  goto RESTART ;
	}
      }
      else if (byte_equal(type,2,DNS_T_MX)) {
	if (!dobytes(2)) return 0;
	if (!doname()) return 0;
      }
      else if (byte_equal(type,2,DNS_T_SOA)) {
	if (!doname()) return 0;
	if (!doname()) return 0;
	if (!dobytes(20)) return 0;
        flaggavesoa = 1;
      }
      else
        if (!response_addbytes(data + dpos,dlen - dpos)) return 0;
      response_rfinish(RESPONSE_ANSWER);
    }
    for (i = 0;i < addr4num;++i)
      if (i < 8) {
	if (!response_rstart(q,DNS_T_A,addr4ttl)) return 0;
	if (!response_addbytes(addr4[i],IP4_LEN)) return 0;
	response_rfinish(RESPONSE_ANSWER);
      }
    for (i = 0;i < addr6num;++i)
      if (i < 8) {
	if (!response_rstart(q,DNS_T_AAAA,addr6ttl)) return 0;
	if (!response_addbytes(addr6[i],IP6_SANS_SCOPE_LEN)) return 0;
	response_rfinish(RESPONSE_ANSWER);
      }

    if (flagfound) break;
    if (wild == control) break;
    if (!*wild) break; /* impossible */
    wild += *wild;
    wild += 1;
  }

  if (!flagfound)
    response_nxdomain();
  else if (byte_equal(qtype,2,DNS_T_ANY)) {
    if (!response_noany(*pqname)) return 0;
  } else if (byte_equal(qtype,2,DNS_T_OPT)) {
    if (!response_noopt(*pqname)) return 0;
  }

  AUTHORITY:
  aupos = response_len;

  if (flagauthoritative && (aupos == anpos)) {
    cdb_findstart(&c);
    while ((r = find(control,0))) {
      if (r == -1) return 0;
      if (byte_equal(type,2,DNS_T_SOA)) {
        if (!response_rstart(control,DNS_T_SOA,ttl)) return 0;
	if (!doname()) return 0;
	if (!doname()) return 0;
	if (!dobytes(20)) return 0;
        response_rfinish(RESPONSE_AUTHORITY);
        break;
      }
    }
  }
  else
    if (want(control,DNS_T_NS)) {
      cdb_findstart(&c);
      while ((r = find(control,0))) {
        if (r == -1) return 0;
        if (byte_equal(type,2,DNS_T_NS)) {
          if (!response_rstart(control,DNS_T_NS,ttl)) return 0;
	  if (!doname()) return 0;
          response_rfinish(RESPONSE_AUTHORITY);
        }
      }
    }

  arpos = response_len;

  for (bpos = anpos; bpos < arpos; bpos += datalen) {
    bpos = dns_packet_skipname(response,arpos,bpos); if (!bpos) return 0;
    bpos = dns_packet_copy(response,arpos,bpos,x,RRFIXED_SIZE); if (!bpos) return 0;
    uint16_unpack_big(x + RRFIXED_DATALEN,&datalen);
    if (byte_equal(x + RRFIXED_TYPE,2,DNS_T_NS)) {
      if (!dns_packet_getname(response,arpos,bpos,&d1)) return 0;
    } else if (byte_equal(x + RRFIXED_TYPE,2,DNS_T_MX) || byte_equal(x + RRFIXED_TYPE,2,DNS_T_HTTPS) || byte_equal(x + RRFIXED_TYPE,2,DNS_T_SVCB)) {
      if (!dns_packet_getname(response,arpos,bpos + 2,&d1)) return 0;
    } else if (byte_equal(x + RRFIXED_TYPE,2,DNS_T_SRV)) {
      if (!dns_packet_getname(response,arpos,bpos + 6,&d1)) return 0;
    } else
      continue;
    case_lowerb(d1,dns_domain_length(d1));
    if (want(d1,DNS_T_A)) {
      cdb_findstart(&c);
      while ((r = find(d1,0))) {
        if (r == -1) return 0;
        if (byte_equal(type,2,DNS_T_A)) {
          if (!response_rstart(d1,DNS_T_A,ttl)) return 0;
          if (!dobytes(IP4_LEN)) return 0;
          response_rfinish(RESPONSE_ADDITIONAL);
        }
      }
    }
    if (want(d1,DNS_T_AAAA)) {
      cdb_findstart(&c);
      while ((r = find(d1,0))) {
        if (r == -1) return 0;
        if (byte_equal(type,2,DNS_T_AAAA)) {
          if (!response_rstart(d1,DNS_T_AAAA,ttl)) return 0;
          if (!dobytes(IP6_SANS_SCOPE_LEN)) return 0;
          response_rfinish(RESPONSE_ADDITIONAL);
        }
      }
    }
  }

  if (flagauthoritative && (response_len > max)) {
    byte_zero(response + RESPONSE_ADDITIONAL,2);
    response_len = arpos;
    if (response_len > max) {
      byte_zero(response + RESPONSE_AUTHORITY,2);
      response_len = aupos;
    }
  }

DONE:
  return 1;
}

static int doit(const char *qname,const char qtype[2],unsigned int max)
{
  int r ;
  char * q = 0 ;

  if (!dns_domain_copy(&q, qname)) return 0 ;
  r = doit1(&q, qtype, max) ;
  dns_domain_free(&q) ;
  return r ;
}

int respond(const char *q,const char qtype[2],unsigned int max,const struct ip_address *ip)
{
  int fd;
  int r;
  char key[6];

  tai_now(&now);
  fd = open_read("data.cdb");
  if (fd == -1) return 0;
  cdb_init(&c,fd);

  byte_zero(clientloc,2);
  if (ip_is4(ip)) {
    key[0] = 0;
    key[1] = '%';
    byte_copy(key + 2,4,ip->d4);
    r = cdb_find(&c,key,6);
    if (!r) r = cdb_find(&c,key,5);
    if (!r) r = cdb_find(&c,key,4);
    if (!r) r = cdb_find(&c,key,3);
    if (!r) r = cdb_find(&c,key,2);
    if (r == -1) { r = 0; goto done; }
    if (r && (cdb_datalen(&c) == 2))
      if (cdb_read(&c,clientloc,2,cdb_datapos(&c)) == -1) { r = 0; goto done; }
  }

  r = doit(q,qtype,max);

done:
  cdb_free(&c);
  close(fd);
  return r;
}
