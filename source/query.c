#include "error.h"
#include "roots.h"
#include "log.h"
#include "case.h"
#include "cache.h"
#include "byte.h"
#include "dns.h"
#include "uint64.h"
#include "uint32.h"
#include "uint16.h"
#include "dd.h"
#include "alloc.h"
#include "response.h"
#include "query.h"

static int flagforwardonly = 0;
static int recursiondesired = 0;

void query_forwardonly(void)
{
  flagforwardonly = 1;
  recursiondesired = 1;
}

void query_forwardfirst(void)
{
  flagforwardonly = 0;
  recursiondesired = 1;
}

static void cachegeneric(const char type[2],const char *d,const char *data,unsigned int datalen,uint32 ttl)
{
  unsigned int len;
  char key[257];

  len = dns_domain_length(d);
  if (len > 255) return;

  byte_copy(key,2,type);
  byte_copy(key + 2,len,d);
  case_lowerb(key + 2,len);

  cache_set(key,len + 2,data,datalen,ttl);
}

static char save_buf[8192];
static unsigned int save_len;
static unsigned int save_ok;

static void save_start(void)
{
  save_len = 0;
  save_ok = 1;
}

static void save_data(const char *buf,unsigned int len)
{
  if (!save_ok) return;
  if (len > (sizeof save_buf) - save_len) { save_ok = 0; return; }
  byte_copy(save_buf + save_len,len,buf);
  save_len += len;
}

static void save_finish(const char type[2],const char *d,uint32 ttl)
{
  if (!save_ok) return;
  cachegeneric(type,d,save_buf,save_len,ttl);
}


static int typematch(const char rtype[2],const char qtype[2])
{
  return byte_equal(qtype,2,rtype) || byte_equal(qtype,2,DNS_T_ANY);
}

static uint32 ttlget(char buf[4])
{
  uint32 ttl;

  uint32_unpack_big(buf,&ttl);
  if (ttl > 1000000000) return 0;
  if (ttl > 604800) return 604800;
  return ttl;
}


static void cleanup(struct query *z)
{
  int j;
  int k;

  dns_transmit_free(&z->dt);
  for (j = 0;j < QUERY_MAXALIAS;++j)
    dns_domain_free(&z->alias[j]);
  for (j = 0;j < QUERY_MAXLEVEL;++j) {
    dns_domain_free(&z->name[j]);
    for (k = 0;k < QUERY_MAXNS;++k)
      dns_domain_free(&z->ns[j][k]);
  }
}

static int move_name_to_alias(struct query *z,uint32 ttl)
{
  int j ;

  if (z->alias[QUERY_MAXALIAS - 1]) return 0 ;
  for (j = QUERY_MAXALIAS - 1;j > 0;--j)
    z->alias[j] = z->alias[j - 1];
  for (j = QUERY_MAXALIAS - 1;j > 0;--j)
    z->aliasttl[j] = z->aliasttl[j - 1];
  z->alias[0] = z->name[0];
  z->aliasttl[0] = ttl;
  z->name[0] = 0;
  return 1 ;
}

static int rqa(struct query *z)
{
  int i;

  for (i = QUERY_MAXALIAS - 1;i >= 0;--i)
    if (z->alias[i]) {
      if (!response_query(z->alias[i],z->type,z->class)) return 0;
      while (i > 0) {
        if (!response_cname(z->alias[i],z->alias[i - 1],z->aliasttl[i])) return 0;
        --i;
      }
      if (!response_cname(z->alias[0],z->name[0],z->aliasttl[0])) return 0;
      return 1;
    }

  if (!response_query(z->name[0],z->type,z->class)) return 0;
  return 1;
}

static int globalip(char *d,char ip[4])
{
  if (dd(d,"",ip) == 4) return 1;
  return 0;
}

static char *t1 = 0;
static char *t2 = 0;
static char *t3 = 0;
static char *referral = 0;
static unsigned int *records = 0;

static int smaller(char *buf,unsigned int len,unsigned int pos1,unsigned int pos2)
{
  char header1[12];
  char header2[12];
  int r;
  unsigned int len1;
  unsigned int len2;

  pos1 = dns_packet_getname(buf,len,pos1,&t1);
  dns_packet_copy(buf,len,pos1,header1,10);
  pos2 = dns_packet_getname(buf,len,pos2,&t2);
  dns_packet_copy(buf,len,pos2,header2,10);

  r = byte_diff(header1,4,header2);
  if (r < 0) return 1;
  if (r > 0) return 0;

  len1 = dns_domain_length(t1);
  len2 = dns_domain_length(t2);
  if (len1 < len2) return 1;
  if (len1 > len2) return 0;

  r = case_diffb(t1,len1,t2);
  if (r < 0) return 1;
  if (r > 0) return 0;

  if (pos1 < pos2) return 1;
  return 0;
}

static int doit(struct query *z,int state)
{
  char key[257];
  char *cached;
  unsigned int cachedlen;
  char *buf;
  unsigned int len;
  const char *whichserver;
  char header[12];
  char misc[20];
  unsigned int rcode;
  unsigned int posanswers;
  uint16 numanswers;
  unsigned int posauthority;
  uint16 numauthority;
  unsigned int posglue;
  uint16 numglue;
  unsigned int pos;
  unsigned int pos2;
  uint16 datalen;
  char *control;
  char *d;
  char *owner_name = 0 ;
  const char *dtype;
  unsigned int dlen;
  int flagout;
  int flagreferral;
  int flagsoa;
  uint32 ttl;
  uint32 soattl;
  int i;
  int j;
  int k;
  int p;
  int q;

  errno = error_io;
  if (state == 1) goto HAVEPACKET;
  if (state == -1) {
    log_servfail(z->name[z->level]);
    goto SERVFAIL;
  }


  NEWNAME:
  if (++z->loop == 100) goto DIE;
  d = z->name[z->level];
  dtype = z->level ? DNS_T_A : z->type;
  dlen = dns_domain_length(d);

  if (globalip(d,misc)) {
    if (z->level) {
      for (k = 0;k < QUERY_MAXNS_A;k += 4)
        if (byte_equal(z->servers_a[z->level - 1] + k,4,"\0\0\0\0")) {
	  byte_copy(z->servers_a[z->level - 1] + k,4,misc);
	  break;
	}
      goto LOWERLEVEL;
    }
    if (!rqa(z)) goto DIE;
    if (typematch(DNS_T_A,dtype)) {
      if (!response_rstart(d,DNS_T_A,655360)) goto DIE;
      if (!response_addbytes(misc,4)) goto DIE;
      response_rfinish(RESPONSE_ANSWER);
    }
    cleanup(z);
    return 1;
  }

  if (dns_domain_equal(d,"\011localhost\0")) {
    if (z->level) {
      for (k = 0;k < QUERY_MAXNS_A;k += 4)
        if (byte_equal(z->servers_a[z->level - 1] + k,4,"\0\0\0\0")) {
	  byte_copy(z->servers_a[z->level - 1] + k,4,"\177\0\0\1");
	  break;
	}
      goto LOWERLEVEL;
    }
    if (!rqa(z)) goto DIE;
    if (typematch(DNS_T_A,dtype)) {
      if (!response_rstart(d,DNS_T_A,655360)) goto DIE;
      if (!response_addbytes("\177\0\0\1",4)) goto DIE;
      response_rfinish(RESPONSE_ANSWER);
    }
    if (typematch(DNS_T_AAAA,dtype)) {
      if (!response_rstart(d,DNS_T_AAAA,655360)) goto DIE;
      if (!response_addbytes("\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\1",16)) goto DIE;
      response_rfinish(RESPONSE_ANSWER);
    }
    cleanup(z);
    return 1;
  }
  if (dns_domain_equal(d,"\0011\0010\0010\003127\7in-addr\4arpa\0")) {
    if (z->level) goto LOWERLEVEL;
    if (!rqa(z)) goto DIE;
    if (typematch(DNS_T_PTR,dtype)) {
      if (!response_rstart(d,DNS_T_PTR,655360)) goto DIE;
      if (!response_addname("\011localhost\0")) goto DIE;
      response_rfinish(RESPONSE_ANSWER);
    }
    cleanup(z);
    log_stats();
    return 1;
  }
  if (dns_domain_equal(d,"\0011\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\3ip6\4arpa\0")) {
    if (z->level) goto LOWERLEVEL;
    if (!rqa(z)) goto DIE;
    if (typematch(DNS_T_PTR,dtype)) {
      if (!response_rstart(d,DNS_T_PTR,655360)) goto DIE;
      if (!response_addname("\011localhost\0")) goto DIE;
      response_rfinish(RESPONSE_ANSWER);
    }
    cleanup(z);
    log_stats();
    return 1;
  }

  if (dlen <= 255) {
    byte_copy(key,2,DNS_T_ANY);
    byte_copy(key + 2,dlen,d);
    case_lowerb(key + 2,dlen);
    cached = cache_get(key,dlen + 2,&cachedlen,&ttl);
    if (cached) {
      log_cachednxdomain(d);
      goto NXDOMAIN;
    }

    byte_copy(key,2,DNS_T_CNAME);
    cached = cache_get(key,dlen + 2,&cachedlen,&ttl);
    /* A previous explicit query might have caused an empty RRSet to have been
    ** cached.  Take care to ignore such a thing. 
    */
    if (cached && cachedlen) {
      if (typematch(DNS_T_CNAME,dtype)) {
        log_cachedanswer(d,DNS_T_CNAME);
        if (!rqa(z)) goto DIE;
	if (!response_cname(z->name[0],cached,ttl)) goto DIE;
	cleanup(z);
	return 1;
      }
      log_cachedcname(d,cached);
      if (!z->level) {
	if (!move_name_to_alias(z,ttl)) goto DIE ;
      }
      if (!dns_domain_copy(&z->name[z->level],cached)) goto DIE;
      goto NEWNAME;
    }

    if (typematch(DNS_T_SOA,dtype)) {
      byte_copy(key,2,DNS_T_SOA);
      cached = cache_get(key,dlen + 2,&cachedlen,&ttl);
      if (cached && (cachedlen || byte_diff(dtype,2,DNS_T_ANY))) {
	log_cachedanswer(d,DNS_T_SOA);
	if (!rqa(z)) goto DIE;
	pos = 0;
	while ((pos = dns_packet_copy(cached,cachedlen,pos,misc,20))) {
	  pos = dns_packet_getname(cached,cachedlen,pos,&t2);
	  if (!pos) break;
	  pos = dns_packet_getname(cached,cachedlen,pos,&t3);
	  if (!pos) break;
	  if (!response_rstart(d,DNS_T_SOA,ttl)) goto DIE;
	  if (!response_addname(t2)) goto DIE;
	  if (!response_addname(t3)) goto DIE;
	  if (!response_addbytes(misc,20)) goto DIE;
	  response_rfinish(RESPONSE_ANSWER);
	}
	cleanup(z);
	return 1;
      }
    }

    if (typematch(DNS_T_NS,dtype)) {
      byte_copy(key,2,DNS_T_NS);
      cached = cache_get(key,dlen + 2,&cachedlen,&ttl);
      if (cached && (cachedlen || byte_diff(dtype,2,DNS_T_ANY))) {
	log_cachedanswer(d,DNS_T_NS);
	if (!rqa(z)) goto DIE;
	pos = 0;
	while ((pos = dns_packet_getname(cached,cachedlen,pos,&t2))) {
	  if (!response_rstart(d,DNS_T_NS,ttl)) goto DIE;
	  if (!response_addname(t2)) goto DIE;
	  response_rfinish(RESPONSE_ANSWER);
	}
	cleanup(z);
	return 1;
      }
    }

    if (typematch(DNS_T_PTR,dtype)) {
      byte_copy(key,2,DNS_T_PTR);
      cached = cache_get(key,dlen + 2,&cachedlen,&ttl);
      if (cached && (cachedlen || byte_diff(dtype,2,DNS_T_ANY))) {
	log_cachedanswer(d,DNS_T_PTR);
	if (!rqa(z)) goto DIE;
	pos = 0;
	while ((pos = dns_packet_getname(cached,cachedlen,pos,&t2))) {
	  if (!response_rstart(d,DNS_T_PTR,ttl)) goto DIE;
	  if (!response_addname(t2)) goto DIE;
	  response_rfinish(RESPONSE_ANSWER);
	}
	cleanup(z);
	return 1;
      }
    }

    if (typematch(DNS_T_MX,dtype)) {
      byte_copy(key,2,DNS_T_MX);
      cached = cache_get(key,dlen + 2,&cachedlen,&ttl);
      if (cached && (cachedlen || byte_diff(dtype,2,DNS_T_ANY))) {
	log_cachedanswer(d,DNS_T_MX);
	if (!rqa(z)) goto DIE;
	pos = 0;
	while ((pos = dns_packet_copy(cached,cachedlen,pos,misc,2))) {
	  pos = dns_packet_getname(cached,cachedlen,pos,&t2);
	  if (!pos) break;
	  if (!response_rstart(d,DNS_T_MX,ttl)) goto DIE;
	  if (!response_addbytes(misc,2)) goto DIE;
	  if (!response_addname(t2)) goto DIE;
	  response_rfinish(RESPONSE_ANSWER);
	}
	cleanup(z);
	return 1;
      }
    }

    if (typematch(DNS_T_A,dtype)) {
      byte_copy(key,2,DNS_T_A);
      cached = cache_get(key,dlen + 2,&cachedlen,&ttl);
      if (cached && (cachedlen || byte_diff(dtype,2,DNS_T_ANY))) {
	log_cachedanswer(d,DNS_T_A);
	if (z->level) {
	  while (cachedlen >= 4) {
	    for (k = 0;k < QUERY_MAXNS_A;k += 4)
	      if (byte_equal(z->servers_a[z->level - 1] + k,4,"\0\0\0\0")) {
		byte_copy(z->servers_a[z->level - 1] + k,4,cached);
		break;
	      }
	    cached += 4;
	    cachedlen -= 4;
	  }
	  goto LOWERLEVEL;
	}

	if (!rqa(z)) goto DIE;
	while (cachedlen >= 4) {
	  if (!response_rstart(d,DNS_T_A,ttl)) goto DIE;
	  if (!response_addbytes(cached,4)) goto DIE;
	  response_rfinish(RESPONSE_ANSWER);
	  cached += 4;
	  cachedlen -= 4;
	}
	cleanup(z);
	return 1;
      }
    }

    if (typematch(DNS_T_AAAA,dtype)) {
      byte_copy(key,2,DNS_T_AAAA);
      cached = cache_get(key,dlen + 2,&cachedlen,&ttl);
      if (cached && (cachedlen || byte_diff(dtype,2,DNS_T_ANY))) {
	log_cachedanswer(d,DNS_T_AAAA);
	if (z->level) {
	  while (cachedlen >= 16) {
	    for (k = 0;k < QUERY_MAXNS_AAAA;k += 4)
	      if (byte_equal(z->servers_aaaa[z->level - 1] + k,16,"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0")) {
		byte_copy(z->servers_aaaa[z->level - 1] + k,16,cached);
		break;
	      }
	    cached += 16;
	    cachedlen -= 16;
	  }
	  goto LOWERLEVEL;
	}

	if (!rqa(z)) goto DIE;
	while (cachedlen >= 16) {
	  if (!response_rstart(d,DNS_T_AAAA,ttl)) goto DIE;
	  if (!response_addbytes(cached,16)) goto DIE;
	  response_rfinish(RESPONSE_ANSWER);
	  cached += 16;
	  cachedlen -= 16;
	}
	cleanup(z);
	return 1;
      }
    }

    if (!typematch(DNS_T_ANY,dtype) && !typematch(DNS_T_AXFR,dtype) && !typematch(DNS_T_SOA,dtype) && !typematch(DNS_T_NS,dtype) && !typematch(DNS_T_PTR,dtype) && !typematch(DNS_T_A,dtype) && !typematch(DNS_T_AAAA,dtype) && !typematch(DNS_T_MX,dtype)) {
      byte_copy(key,2,dtype);
      cached = cache_get(key,dlen + 2,&cachedlen,&ttl);
      if (cached && (cachedlen || byte_diff(dtype,2,DNS_T_ANY))) {
	log_cachedanswer(d,dtype);
	if (!rqa(z)) goto DIE;
	while (cachedlen >= 2) {
	  uint16_unpack_big(cached,&datalen);
	  cached += 2;
	  cachedlen -= 2;
	  if (datalen > cachedlen) goto DIE;
	  if (!response_rstart(d,dtype,ttl)) goto DIE;
	  if (!response_addbytes(cached,datalen)) goto DIE;
	  response_rfinish(RESPONSE_ANSWER);
	  cached += datalen;
	  cachedlen -= datalen;
	}
	cleanup(z);
	return 1;
      }
    }
  }

  for (;;) {
    if (roots(z->servers_a[z->level],d)) {
      for (j = 0;j < QUERY_MAXNS;++j)
        dns_domain_free(&z->ns[z->level][j]);
      z->control[z->level] = d;
      break;
    }

    if (!flagforwardonly && (z->level < 2))
      if (dlen < 255) {
        byte_copy(key,2,DNS_T_NS);
        byte_copy(key + 2,dlen,d);
        case_lowerb(key + 2,dlen);
        cached = cache_get(key,dlen + 2,&cachedlen,&ttl);
        if (cached && cachedlen) {
	  z->control[z->level] = d;
          byte_zero(z->servers_a[z->level],QUERY_MAXNS_A);
          byte_zero(z->servers_aaaa[z->level],QUERY_MAXNS_AAAA);
          for (j = 0;j < QUERY_MAXNS;++j)
            dns_domain_free(&z->ns[z->level][j]);
          pos = 0;
          j = 0;
          while ((pos = dns_packet_getname(cached,cachedlen,pos,&t1))) {
	    log_cachedns(d,t1);
            if (j < QUERY_MAXNS)
              if (!dns_domain_copy(&z->ns[z->level][j++],t1)) goto DIE;
	  }
          break;
        }
      }

    if (!*d) goto DIE;
    j = 1 + (unsigned int) (unsigned char) *d;
    dlen -= j;
    d += j;
  }


  HAVENS:
  for (j = 0;j < QUERY_MAXNS;++j)
    if (z->ns[z->level][j]) {
      if (z->level + 1 < QUERY_MAXLEVEL) {
        if (!dns_domain_copy(&z->name[z->level + 1],z->ns[z->level][j])) goto DIE;
        dns_domain_free(&z->ns[z->level][j]);
        ++z->level;
        goto NEWNAME;
      }
      dns_domain_free(&z->ns[z->level][j]);
    }

  for (j = 0;j < QUERY_MAXNS_A;j += 4)
    if (byte_diff(z->servers_a[z->level] + j,4,"\0\0\0\0"))
      break;
  if (j == QUERY_MAXNS_A) goto SERVFAIL;

  dns_sortip(z->servers_a[z->level],QUERY_MAXNS_A);
  dtype = z->level ? DNS_T_A : z->type;
  log_tx(z->name[z->level],dtype,z->control[z->level],z->servers_a[z->level],z->level);
  if (dns_transmit_start(&z->dt,z->servers_a[z->level],recursiondesired,z->name[z->level],dtype,z->localip) == -1) goto DIE;
  return 0;


  LOWERLEVEL:
  dns_domain_free(&z->name[z->level]);
  for (j = 0;j < QUERY_MAXNS;++j)
    dns_domain_free(&z->ns[z->level][j]);
  --z->level;
  goto HAVENS;


  HAVEPACKET:
  if (++z->loop == 100) goto DIE;
  buf = z->dt.packet;
  len = z->dt.packetlen;

  whichserver = z->dt.servers + 4 * z->dt.curserver;
  control = z->control[z->level];
  d = z->name[z->level];
  dtype = z->level ? DNS_T_A : z->type;

  pos = dns_packet_copy(buf,len,0,header,12); if (!pos) goto DIE;
  pos = dns_packet_skipname(buf,len,pos); if (!pos) goto DIE;
  pos += 4;
  posanswers = pos;

  uint16_unpack_big(header + 6,&numanswers);
  uint16_unpack_big(header + 8,&numauthority);
  uint16_unpack_big(header + 10,&numglue);

  rcode = header[3] & 15;
  if (rcode && (rcode != 3)) goto DIE; /* impossible; see irrelevant() */

  flagout = 0;
  flagreferral = 0;
  flagsoa = 0;
  soattl = 0;
  if (!dns_domain_copy(&owner_name,d)) goto DIE;
  /* This code assumes that the CNAME chain is presented in the correct 
  ** order.  The example algorithm in RFC 1034 will actually result in this
  ** being the case, but the words do not require it to be so.
  */
  for (j = 0;j < numanswers;++j) {
    pos = dns_packet_getname(buf,len,pos,&t1); if (!pos) goto DIE;
    pos = dns_packet_copy(buf,len,pos,header,10); if (!pos) goto DIE;

    if (dns_domain_equal(t1,owner_name))
      if (byte_equal(header + 2,2,DNS_C_IN)) { /* should always be true */
        if (typematch(header,dtype))
          flagout = 1;
        else if (typematch(header,DNS_T_CNAME)) {
          if (!dns_packet_getname(buf,len,pos,&owner_name)) goto DIE;
        }
      }
  
    uint16_unpack_big(header + 8,&datalen);
    pos += datalen;
  }
  dns_domain_free(&owner_name) ;
  posauthority = pos;

  for (j = 0;j < numauthority;++j) {
    pos = dns_packet_getname(buf,len,pos,&t1); if (!pos) goto DIE;
    pos = dns_packet_copy(buf,len,pos,header,10); if (!pos) goto DIE;

    if (typematch(header,DNS_T_SOA)) {
      flagsoa = 1;
      soattl = ttlget(header + 4);
      if (soattl > 3600) soattl = 3600;
    }
    else if (typematch(header,DNS_T_NS)) {
      flagreferral = 1;
      if (!dns_domain_copy(&referral,t1)) goto DIE;
    }

    uint16_unpack_big(header + 8,&datalen);
    pos += datalen;
  }
  posglue = pos;

  if (records) { alloc_free(records); records = 0; }

  k = numanswers + numauthority + numglue;
  records = (unsigned int *) alloc(k * sizeof(unsigned int));
  if (!records) goto DIE;

  pos = posanswers;
  for (j = 0;j < k;++j) {
    records[j] = pos;
    pos = dns_packet_getname(buf,len,pos,&t1); if (!pos) goto DIE;
    pos = dns_packet_copy(buf,len,pos,header,10); if (!pos) goto DIE;
    uint16_unpack_big(header + 8,&datalen);
    pos += datalen;
  }

  i = j = k;
  while (j > 1) {
    if (i > 1) { --i; pos = records[i - 1]; }
    else { pos = records[j - 1]; records[j - 1] = records[i - 1]; --j; }

    q = i;
    while ((p = q * 2) < j) {
      if (!smaller(buf,len,records[p],records[p - 1])) ++p;
      records[q - 1] = records[p - 1]; q = p;
    }
    if (p == j) {
      records[q - 1] = records[p - 1]; q = p;
    }
    while ((q > i) && smaller(buf,len,records[(p = q/2) - 1],pos)) {
      records[q - 1] = records[p - 1]; q = p;
    }
    records[q - 1] = pos;
  }

  for (i = 0;i < k;i = j) {
    char type[2];

    j = i + 1;

    pos = dns_packet_getname(buf,len,records[i],&t1); if (!pos) goto DIE;
    pos = dns_packet_copy(buf,len,pos,header,10); if (!pos) goto DIE;
    ttl = ttlget(header + 4);

    byte_copy(type,2,header);
    if (byte_diff(header + 2,2,DNS_C_IN)) continue;

    while (j < k) {
      pos = dns_packet_getname(buf,len,records[j],&t2); if (!pos) goto DIE;
      pos = dns_packet_copy(buf,len,pos,header,10); if (!pos) goto DIE;
      if (!dns_domain_equal(t1,t2)) break;
      if (byte_diff(header,2,type)) break;
      if (byte_diff(header + 2,2,DNS_C_IN)) break;
      ++j;
    }

    if (!dns_domain_suffix(t1,control)) continue;
    if (!roots_same(t1,control)) continue;

    if (byte_equal(type,2,DNS_T_ANY))
      ;
    else if (byte_equal(type,2,DNS_T_AXFR))
      ;
    else if (byte_equal(type,2,DNS_T_SOA)) {
      int done_one = 0;
      save_start();
      while (i < j) {
        pos = dns_packet_skipname(buf,len,records[i]); if (!pos) goto DIE;
        pos = dns_packet_getname(buf,len,pos + 10,&t2); if (!pos) goto DIE;
        pos = dns_packet_getname(buf,len,pos,&t3); if (!pos) goto DIE;
        pos = dns_packet_copy(buf,len,pos,misc,20); if (!pos) goto DIE;
	/* It is unfortunately necessary to avoid caching the SOA RRSETs that
	** people send to us in the authority section, as they have usually
	** been modified to convey TTLs for empty RRSETs and no-such-name 
	** answers.
	*/
        if (records[i] < posauthority) {
	  log_rrsoa(whichserver,t1,t2,t3,misc,ttl);
	  save_data(misc,20);
	  save_data(t2,dns_domain_length(t2));
	  save_data(t3,dns_domain_length(t3));
	  done_one = 1;
	}
        ++i;
      }
      if (done_one)
	save_finish(DNS_T_SOA,t1,ttl);
    }
    else if (byte_equal(type,2,DNS_T_CNAME)) {
      pos = dns_packet_skipname(buf,len,records[j - 1]); if (!pos) goto DIE;
      pos = dns_packet_getname(buf,len,pos + 10,&t2); if (!pos) goto DIE;
      log_rrcname(whichserver,t1,t2,ttl);
      cachegeneric(DNS_T_CNAME,t1,t2,dns_domain_length(t2),ttl);
    }
    else if (byte_equal(type,2,DNS_T_PTR)) {
      save_start();
      while (i < j) {
        pos = dns_packet_skipname(buf,len,records[i]); if (!pos) goto DIE;
        pos = dns_packet_getname(buf,len,pos + 10,&t2); if (!pos) goto DIE;
        log_rrptr(whichserver,t1,t2,ttl);
        save_data(t2,dns_domain_length(t2));
        ++i;
      }
      save_finish(DNS_T_PTR,t1,ttl);
    }
    else if (byte_equal(type,2,DNS_T_NS)) {
      save_start();
      while (i < j) {
        pos = dns_packet_skipname(buf,len,records[i]); if (!pos) goto DIE;
        pos = dns_packet_getname(buf,len,pos + 10,&t2); if (!pos) goto DIE;
        log_rrns(whichserver,t1,t2,ttl);
        save_data(t2,dns_domain_length(t2));
        ++i;
      }
      save_finish(DNS_T_NS,t1,ttl);
    }
    else if (byte_equal(type,2,DNS_T_MX)) {
      save_start();
      while (i < j) {
        pos = dns_packet_skipname(buf,len,records[i]); if (!pos) goto DIE;
        pos = dns_packet_copy(buf,len,pos + 10,misc,2); if (!pos) goto DIE;
        pos = dns_packet_getname(buf,len,pos,&t2); if (!pos) goto DIE;
        log_rrmx(whichserver,t1,t2,misc,ttl);
        save_data(misc,2);
        save_data(t2,dns_domain_length(t2));
        ++i;
      }
      save_finish(DNS_T_MX,t1,ttl);
    }
    else if (byte_equal(type,2,DNS_T_A)) {
      save_start();
      while (i < j) {
        pos = dns_packet_skipname(buf,len,records[i]); if (!pos) goto DIE;
        pos = dns_packet_copy(buf,len,pos,header,10); if (!pos) goto DIE;
        if (byte_equal(header + 8,2,"\0\4")) {
          pos = dns_packet_copy(buf,len,pos,header,4); if (!pos) goto DIE;
          save_data(header,4);
          log_rr(whichserver,t1,DNS_T_A,header,4,ttl);
        }
        ++i;
      }
      save_finish(DNS_T_A,t1,ttl);
    }
    else if (byte_equal(type,2,DNS_T_AAAA)) {
      save_start();
      while (i < j) {
        pos = dns_packet_skipname(buf,len,records[i]); if (!pos) goto DIE;
        pos = dns_packet_copy(buf,len,pos,header,10); if (!pos) goto DIE;
        if (byte_equal(header + 8,2,"\0\020")) {
          pos = dns_packet_copy(buf,len,pos,header,16); if (!pos) goto DIE;
          save_data(header,16);
          log_rr(whichserver,t1,DNS_T_AAAA,header,16,ttl);
        }
        ++i;
      }
      save_finish(DNS_T_AAAA,t1,ttl);
    }
    else {
      save_start();
      while (i < j) {
        pos = dns_packet_skipname(buf,len,records[i]); if (!pos) goto DIE;
        pos = dns_packet_copy(buf,len,pos,header,10); if (!pos) goto DIE;
        uint16_unpack_big(header + 8,&datalen);
        if (datalen > len - pos) goto DIE;
        save_data(header + 8,2);
        save_data(buf + pos,datalen);
        log_rr(whichserver,t1,type,buf + pos,datalen,ttl);
        ++i;
      }
      save_finish(type,t1,ttl);
    }
  }

  alloc_free(records); records = 0;

  if (byte_diff(DNS_T_CNAME,2,dtype)) {
    /* This code assumes that the CNAME chain is presented in the correct 
    ** order.  The example algorithm in RFC 1034 will actually result in this
    ** being the case, but the words do not require it to be so.
    */
    pos = posanswers;
    for (j = 0;j < numanswers;++j) {
      pos = dns_packet_getname(buf,len,pos,&t1); if (!pos) goto DIE;
      pos = dns_packet_copy(buf,len,pos,header,10); if (!pos) goto DIE;

      if (dns_domain_equal(t1,d))
	if (byte_equal(header + 2,2,DNS_C_IN)) { /* should always be true */
	  if (typematch(header,DNS_T_CNAME)) {
	    ttl = ttlget(header + 4);
	    if (z->level == 0) {
	      if (!move_name_to_alias(z,ttl)) goto DIE ;
	    }
	    if (!dns_packet_getname(buf,len,pos,&z->name[z->level])) goto DIE;
	    d = z->name[z->level];
	    if (!dns_domain_suffix(d,control) || !roots_same(d,control))
	      goto NEWNAME ;  /* Cannot trust the chain further - restart using current name */
	  }
	}

      uint16_unpack_big(header + 8,&datalen);
      pos += datalen;
    }
  }

  /* A "no such name" error applies to the end of any CNAME chain, not to the start. */
  if (rcode == 3) {
    log_nxdomain(whichserver,d,soattl);
    cachegeneric(DNS_T_ANY,d,"",0,soattl);

    NXDOMAIN:
    if (z->level) goto LOWERLEVEL;
    if (!rqa(z)) goto DIE;
    response_nxdomain();
    cleanup(z);
    return 1;
  }

  /* We check for a lame server _after_ we have cached any records that it
  ** might have returned to us.  This copes better with the incorrect
  ** behaviour of one content DNS server software that doesn't return
  ** complete CNAME chains but instead returns only the first link in a
  ** chain followed by a lame delegation to the same server.
  ** Also: We check for a lame server _after_ following the CNAME chain.  The
  ** delegation in a referral answer applies to the _end_ of the chain, not
  ** to the beginning.
  */
  if (!rcode && !flagout && flagreferral && !flagsoa)
    if (dns_domain_equal(referral,control) || !dns_domain_suffix(referral,control)) {
      log_lame(whichserver,control,referral);
      byte_zero(whichserver,4);
      goto HAVENS;
    }

  if (!flagout && flagsoa)
    /* Don't save empty RRSets for those types that we use as special markers. */
    if (byte_diff(DNS_T_ANY,2,dtype))
      if (byte_diff(DNS_T_AXFR,2,dtype)) {
          save_start();
          save_finish(dtype,d,soattl);
	  log_nodata(whichserver,d,dtype,soattl);
        }

  log_stats();


  if (flagout || flagsoa || !flagreferral) {
    if (z->level) {
      pos = posanswers;
      for (j = 0;j < numanswers;++j) {
        pos = dns_packet_getname(buf,len,pos,&t1); if (!pos) goto DIE;
        pos = dns_packet_copy(buf,len,pos,header,10); if (!pos) goto DIE;
        uint16_unpack_big(header + 8,&datalen);
        if (dns_domain_equal(t1,d))
	  if (byte_equal(header + 2,2,DNS_C_IN)) { /* should always be true */
	    if (typematch(header,DNS_T_A)) {
              if (datalen == 4)
                for (k = 0;k < QUERY_MAXNS_A;k += 4)
                  if (byte_equal(z->servers_a[z->level - 1] + k,4,"\0\0\0\0")) {
                    if (!dns_packet_copy(buf,len,pos,z->servers_a[z->level - 1] + k,4)) goto DIE;
                    break;
                  }
	    } else if (typematch(header,DNS_T_AAAA)) {
              if (16 == datalen)
                for (k = 0;k < QUERY_MAXNS_AAAA;k += 16)
                  if (byte_equal(z->servers_aaaa[z->level - 1] + k,16,"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0")) {
                    if (!dns_packet_copy(buf,len,pos,z->servers_aaaa[z->level - 1] + k,16)) goto DIE;
                    break;
                  }
	    }
	  }
        pos += datalen;
      }
      goto LOWERLEVEL;
    }

    if (!rqa(z)) goto DIE;

    pos = posanswers;
    for (j = 0;j < numanswers;++j) {
      pos = dns_packet_getname(buf,len,pos,&t1); if (!pos) goto DIE;
      pos = dns_packet_copy(buf,len,pos,header,10); if (!pos) goto DIE;
      ttl = ttlget(header + 4);
      uint16_unpack_big(header + 8,&datalen);
      if (dns_domain_equal(t1,d))
        if (byte_equal(header + 2,2,DNS_C_IN)) /* should always be true */
          if (typematch(header,dtype)) {
            if (!response_rstart(t1,header,ttl)) goto DIE;
  
            if (typematch(header,DNS_T_NS) || typematch(header,DNS_T_CNAME) || typematch(header,DNS_T_PTR)) {
              if (!dns_packet_getname(buf,len,pos,&t2)) goto DIE;
              if (!response_addname(t2)) goto DIE;
            }
            else if (typematch(header,DNS_T_MX)) {
              pos2 = dns_packet_copy(buf,len,pos,misc,2); if (!pos2) goto DIE;
              if (!response_addbytes(misc,2)) goto DIE;
              if (!dns_packet_getname(buf,len,pos2,&t2)) goto DIE;
              if (!response_addname(t2)) goto DIE;
            }
            else if (typematch(header,DNS_T_SOA)) {
              pos2 = dns_packet_getname(buf,len,pos,&t2); if (!pos2) goto DIE;
              if (!response_addname(t2)) goto DIE;
              pos2 = dns_packet_getname(buf,len,pos2,&t3); if (!pos2) goto DIE;
              if (!response_addname(t3)) goto DIE;
              pos2 = dns_packet_copy(buf,len,pos2,misc,20); if (!pos2) goto DIE;
              if (!response_addbytes(misc,20)) goto DIE;
            }
            else {
              if (pos + datalen > len) goto DIE;
              if (!response_addbytes(buf + pos,datalen)) goto DIE;
            }
  
            response_rfinish(RESPONSE_ANSWER);
          }
      pos += datalen;
    }

    cleanup(z);
    return 1;
  }


  if (!dns_domain_suffix(d,referral)) goto DIE;

  /* In strict "forwardonly" mode, we don't, as the manual states,
  ** contact a chain of servers according to "NS" resource records.
  ** We don't obey any referral responses, therefore.  Instead, we
  ** eliminate the server from the list and try the next one.
  */
  if (flagforwardonly) {
      log_ignore_referral(whichserver,control,referral);
      byte_zero(whichserver,4);
      goto HAVENS;
  }

  control = d + dns_domain_suffixpos(d,referral);
  z->control[z->level] = control;
  byte_zero(z->servers_a[z->level],QUERY_MAXNS_A);
  byte_zero(z->servers_aaaa[z->level],QUERY_MAXNS_AAAA);
  for (j = 0;j < QUERY_MAXNS;++j)
    dns_domain_free(&z->ns[z->level][j]);
  k = 0;

  pos = posauthority;
  for (j = 0;j < numauthority;++j) {
    pos = dns_packet_getname(buf,len,pos,&t1); if (!pos) goto DIE;
    pos = dns_packet_copy(buf,len,pos,header,10); if (!pos) goto DIE;
    uint16_unpack_big(header + 8,&datalen);
    if (dns_domain_equal(referral,t1)) /* should always be true */
      if (typematch(header,DNS_T_NS)) /* should always be true */
        if (byte_equal(header + 2,2,DNS_C_IN)) /* should always be true */
          if (k < QUERY_MAXNS)
            if (!dns_packet_getname(buf,len,pos,&z->ns[z->level][k++])) goto DIE;
    pos += datalen;
  }

  goto HAVENS;


  SERVFAIL:
  if (z->level) goto LOWERLEVEL;
  if (!rqa(z)) goto DIE;
  response_servfail();
  cleanup(z);
  return 1;


  DIE:
  cleanup(z);
  if (records) { alloc_free(records); records = 0; }
  dns_domain_free(&owner_name) ;
  return -1;
}

int query_start(struct query *z,char *dn,char type[2],char class[2],char localip[4])
{
  if (byte_equal(type,2,DNS_T_AXFR)) { errno = error_perm; return -1; }

  cleanup(z);
  z->level = 0;
  z->loop = 0;

  if (!dns_domain_copy(&z->name[0],dn)) return -1;
  byte_copy(z->type,2,type);
  byte_copy(z->class,2,class);
  byte_copy(z->localip,4,localip);

  return doit(z,0);
}

int query_get(struct query *z,iopause_fd *x,struct taia *stamp)
{
  switch(dns_transmit_get(&z->dt,x,stamp)) {
    case 1:
      return doit(z,1);
    case -1:
      return doit(z,-1);
  }
  return 0;
}

void query_io(struct query *z,iopause_fd *x,struct taia *deadline)
{
  dns_transmit_io(&z->dt,x,deadline);
}
