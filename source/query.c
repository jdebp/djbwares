#include "error.h"
#include "roots.h"
#include "log.h"
#include "case.h"
#include "cache.h"
#include "byte.h"
#include "dns_transmit.h"
#include "dns_domain.h"
#include "dns_packet.h"
#include "dns_constants.h"
#include "dns_sortip.h"
#include "dns_nd.h"
#include "uint64.h"
#include "uint32.h"
#include "uint16.h"
#include "dd.h"
#include "alloc.h"
#include "response.h"
#include "query.h"
#include "ip.h"

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
  return byte_equal(qtype,2,rtype);
}

static int internetclass(const char rclass[2])
{
  return byte_equal(rclass,2,DNS_C_IN);
}

static uint32 ttlget(const char buf[4])
{
  uint32 ttl;

  uint32_unpack_big(buf,&ttl);
  if (ttl > TTL_ARITH_OVERFLOW) return 0;
  if (ttl > TTL_CACHE_CAP) return TTL_CACHE_CAP;
  return ttl;
}


static void reset_nameserver_addresses(struct query *z,unsigned int level)
{
  unsigned int k;
  z->server_count[level] = 0U;
  for (k = 0;k < QUERY_MAXNS_ADDR;++k)
    ip_make_unassigned(&z->server_addresses[level][k]);
}

static void cleanup_nameserver_names(struct query *z,unsigned int level)
{
  unsigned int k;
  for (k = 0;k < QUERY_MAXNS;++k)
    dns_domain_free(&z->ns[level][k]);
}

static void cleanup(struct query *z)
{
  unsigned int j;

  dns_transmit_free(&z->dt);
  for (j = 0;j < QUERY_MAXALIAS;++j)
    dns_domain_free(&z->alias[j]);
  for (j = 0;j < QUERY_MAXLEVEL;++j) {
    dns_domain_free(&z->name[j]);
    cleanup_nameserver_names(z,j);
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

static int rqa(const struct query *z)
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

static char *t1 = 0;
static char *t2 = 0;
static char *t3 = 0;
static char *referral = 0;

static int smaller(const char *buf,unsigned int len,unsigned int pos1,unsigned int pos2)
{
  char rrfixed1[RRFIXED_SIZE];
  char rrfixed2[RRFIXED_SIZE];
  int r;
  unsigned int len1;
  unsigned int len2;

  pos1 = dns_packet_getname(buf,len,pos1,&t1);
  dns_packet_copy(buf,len,pos1,rrfixed1,sizeof rrfixed1);
  pos2 = dns_packet_getname(buf,len,pos2,&t2);
  dns_packet_copy(buf,len,pos2,rrfixed2,sizeof rrfixed2);

  r = byte_diff(rrfixed1,4,rrfixed2);
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

static const char alt[] = "\003alt";
static const char onion[] = "\005onion";
static const char local[] = "\005local";
static const char invalid[] = "\007invalid";
static const char localhost[] = "\011localhost";
static const char ip6arpa[] = "\003ip6\004arpa";
static const char inaddrarpa[] = "\007in-addr\004arpa";
static const char servicearpa[] = "\007service\004arpa";
static const char resolverarpa[] = "\010resolver\004arpa";

/* The set of fixed built-in responses that proxy DNS servers should/must give.
** Note that this is subtly different to the fixed built-in responses that content DNS servers or DNS client libraries should/must give.
*/
static int handle_specials(struct query *z,const char *d,const char dtype[2])
{
  char ip4[IP4_LEN];
  char ip6[IP6_SANS_SCOPE_LEN];

  if (dd4(d,"",ip4) == IP4_LEN) {
    log_synthetic(d,dtype,z->level,TTL_STATIC_POSITIVE);
    if (!rqa(z)) return -1;
    if (typematch(DNS_T_ANY,dtype)) {
      if (!response_noany(d)) return -1;
      if (!response_placeholder_soa("",TTL_STATIC_NEGATIVE)) return -1;
    } else if (typematch(DNS_T_OPT,dtype)) {
      if (!response_noopt(d)) return -1;
      if (!response_placeholder_soa("",TTL_STATIC_NEGATIVE)) return -1;
    } else if (typematch(DNS_T_AXFR,dtype)||typematch(DNS_T_IXFR,dtype)) {
      if (!response_noaxfr(d)) return -1;
      if (!response_placeholder_soa("",TTL_STATIC_NEGATIVE)) return -1;
    } else if (typematch(DNS_T_A,dtype)) {
      if (!response_rstart(d,DNS_T_A,TTL_STATIC_POSITIVE)) return -1;
      if (!response_addbytes(ip4,sizeof ip4)) return -1;
      response_rfinish(RESPONSE_ANSWER);
      if (!response_badip4(d)) return -1;
    } else if (typematch(DNS_T_AAAA,dtype)) {
      byte_zero(ip6, sizeof ip6);
      byte_copy(ip6 + sizeof ip6 - sizeof ip4,sizeof ip4,ip4);
      ip6[10] = ip6[11] = 0xFF;
      if (!response_rstart(d,DNS_T_AAAA,TTL_STATIC_POSITIVE)) return -1;
      if (!response_addbytes(ip6,sizeof ip6)) return -1;
      response_rfinish(RESPONSE_ANSWER);
      if (!response_badip4(d)) return -1;
    } else {
      if (!response_placeholder_soa("",TTL_STATIC_NEGATIVE)) return -1;
    }
    return 1;
  } else
  if (dns_domain_suffix(d,inaddrarpa)) {
    if (IP4_LEN == dd4(d,inaddrarpa,ip4)) {
      if (127 == (unsigned char)ip4[3]) {
        log_synthetic(d,dtype,z->level,TTL_STATIC_NEGATIVE);
        if (!rqa(z)) return -1;
        if (typematch(DNS_T_ANY,dtype)) {
          if (!response_noany(d)) return -1;
          if (!response_placeholder_soa(inaddrarpa,TTL_STATIC_NEGATIVE)) return -1;
        } else if (typematch(DNS_T_OPT,dtype)) {
          if (!response_noopt(d)) return -1;
          if (!response_placeholder_soa(inaddrarpa,TTL_STATIC_NEGATIVE)) return -1;
        } else if (typematch(DNS_T_AXFR,dtype)||typematch(DNS_T_IXFR,dtype)) {
          if (!response_noaxfr(d)) return -1;
          if (!response_placeholder_soa(inaddrarpa,TTL_STATIC_NEGATIVE)) return -1;
        } else if (typematch(DNS_T_PTR,dtype)) {
          if (!response_rstart(d,DNS_T_PTR,TTL_STATIC_POSITIVE)) return -1;
          if (0 == (unsigned char)ip4[2]
          &&  0 == (unsigned char)ip4[1]
          &&  1 == (unsigned char)ip4[0]
          ) {
            if (!response_addname(localhost)) return -1;
          } else {
            char name[DNS_NAME4_LDOMAIN];

            byte_reverse(ip4, sizeof ip4); /* They are little-endian in the domain name. */
            dns_name4_ldomain(name,ip4);
            if (!response_addname(name)) return -1;
          }
          response_rfinish(RESPONSE_ANSWER);
        } else {
          if (!response_placeholder_soa(inaddrarpa,TTL_STATIC_NEGATIVE)) return -1;
        }
        return 1;
      } else
      if (169 == (unsigned char)ip4[3] && 0xFE == (unsigned char)ip4[2]) {    /* RFC 6762 */
        log_synthetic(d,dtype,z->level,TTL_STATIC_NEGATIVE);
        if (!rqa(z)) return -1;
        if (typematch(DNS_T_ANY,dtype)) {
          if (!response_noany(d)) return -1;
        } else if (typematch(DNS_T_OPT,dtype)) {
          if (!response_noopt(d)) return -1;
        } else if (typematch(DNS_T_AXFR,dtype)||typematch(DNS_T_IXFR,dtype)) {
          if (!response_noaxfr(d)) return -1;
        }
        if (!response_placeholder_soa(inaddrarpa,TTL_STATIC_NEGATIVE)) return -1;
        return 1;
      }
    }
  } else
  if (dns_domain_suffix(d,ip6arpa)) {
    if (IP6_SANS_SCOPE_LEN * 2 == dd6(d,ip6arpa,ip6)) {
      if (byte_equal("\001\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000",IP6_SANS_SCOPE_LEN,ip6)) {
        log_synthetic(d,dtype,z->level,TTL_STATIC_POSITIVE);
        if (!rqa(z)) return -1;
        if (typematch(DNS_T_ANY,dtype)) {
          if (!response_noany(d)) return -1;
          if (!response_placeholder_soa(ip6arpa,TTL_STATIC_NEGATIVE)) return -1;
        } else if (typematch(DNS_T_OPT,dtype)) {
          if (!response_noopt(d)) return -1;
          if (!response_placeholder_soa(ip6arpa,TTL_STATIC_NEGATIVE)) return -1;
        } else if (typematch(DNS_T_AXFR,dtype)||typematch(DNS_T_IXFR,dtype)) {
          if (!response_noaxfr(d)) return -1;
          if (!response_placeholder_soa(ip6arpa,TTL_STATIC_NEGATIVE)) return -1;
        } else if (typematch(DNS_T_PTR,dtype)) {
          if (!response_rstart(d,DNS_T_PTR,TTL_STATIC_POSITIVE)) return -1;
          if (!response_addname(localhost)) return -1;
          response_rfinish(RESPONSE_ANSWER);
        } else {
          if (!response_placeholder_soa(ip6arpa,TTL_STATIC_NEGATIVE)) return -1;
        }
        return 1;
      } else
      if (0xFE == (unsigned char)ip6[15] && (0x80 <= (unsigned char)ip6[14] && (unsigned char)ip6[14] < 0xA0)) {    /* RFC 6762 */
        log_synthetic(d,dtype,z->level,TTL_STATIC_NEGATIVE);
        if (!rqa(z)) return -1;
        if (typematch(DNS_T_ANY,dtype)) {
          if (!response_noany(d)) return -1;
        } else if (typematch(DNS_T_OPT,dtype)) {
          if (!response_noopt(d)) return -1;
        } else if (typematch(DNS_T_AXFR,dtype)||typematch(DNS_T_IXFR,dtype)) {
          if (!response_noaxfr(d)) return -1;
        }
        if (!response_placeholder_soa(ip6arpa,TTL_STATIC_NEGATIVE)) return -1;
        return 1;
      }
    }
  } else
  if (dns_domain_suffix(d,localhost)) {
    log_synthetic(d,dtype,z->level,TTL_STATIC_POSITIVE);
    if (!rqa(z)) return -1;
    if (typematch(DNS_T_ANY,dtype)) {
      if (!response_noany(d)) return -1;
      if (!response_placeholder_soa(localhost,TTL_STATIC_NEGATIVE)) return -1;
    } else if (typematch(DNS_T_OPT,dtype)) {
      if (!response_noopt(d)) return -1;
      if (!response_placeholder_soa(localhost,TTL_STATIC_NEGATIVE)) return -1;
    } else if (typematch(DNS_T_AXFR,dtype)||typematch(DNS_T_IXFR,dtype)) {
      if (!response_noaxfr(d)) return -1;
      if (!response_placeholder_soa(localhost,TTL_STATIC_NEGATIVE)) return -1;
    } else if (IP4_LEN == dd4(d,localhost,ip4) && 127 == (unsigned char)ip4[3]) {
      if (typematch(DNS_T_A,dtype)) {
        if (!response_rstart(d,DNS_T_A,TTL_STATIC_POSITIVE)) return -1;
        byte_reverse(ip4, sizeof ip4); /* They are little-endian in the domain name. */
        if (!response_addbytes(ip4, sizeof ip4)) return -1;
        response_rfinish(RESPONSE_ANSWER);
      } else if (typematch(DNS_T_AAAA,dtype)) {
        byte_zero(ip6, sizeof ip6);
        byte_reverse(ip4, sizeof ip4); /* They are little-endian in the domain name. */
        byte_copy(ip6 + sizeof ip6 - sizeof ip4,sizeof ip4,ip4);
        ip6[10] = ip6[11] = 0xFF;
        if (!response_rstart(d,DNS_T_AAAA,TTL_STATIC_POSITIVE)) return -1;
        if (!response_addbytes(ip6,sizeof ip6)) return -1;
        response_rfinish(RESPONSE_ANSWER);
      }
    } else {
      if (typematch(DNS_T_A,dtype)) {
        if (!response_rstart(d,DNS_T_A,TTL_STATIC_POSITIVE)) return -1;
        if (!response_addbytes("\177\0\0\1",IP4_LEN)) return -1;
        response_rfinish(RESPONSE_ANSWER);
      } else if (typematch(DNS_T_AAAA,dtype)) {
        if (!response_rstart(d,DNS_T_AAAA,TTL_STATIC_POSITIVE)) return -1;
        if (!response_addbytes("\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\1",IP6_SANS_SCOPE_LEN)) return -1;
        response_rfinish(RESPONSE_ANSWER);
      }
    }
    return 1;
  } else
  if (dns_domain_suffix(d,resolverarpa)     /* RFC 9462 */
  ||  dns_domain_suffix(d,invalid)          /* RFC 6761 */
  ||  dns_domain_suffix(d,onion)            /* RFC 7686 */
  ||  dns_domain_suffix(d,local)            /* RFC 6762 */
  ||  dns_domain_suffix(d,alt)              /* RFC 9476 */
  ) {
    log_synthetic(d,dtype,z->level,TTL_STATIC_NEGATIVE);
    if (!rqa(z)) return -1;
    if (!response_placeholder_soa(d,TTL_STATIC_NEGATIVE)) return -1;
    response_nxdomain();
    return 1;
  } else
  if (dns_domain_suffix(d,servicearpa)) {   /* RFC 9665 */
    log_synthetic(d,dtype,z->level,TTL_STATIC_NEGATIVE);
    if (!rqa(z)) return -1;
    if (!dns_domain_equal(d,servicearpa)
    &&  !dns_domain_equal(d,"\007default\007service\004arpa")
    ) {
      response_nxdomain();
    } else if (typematch(DNS_T_ANY,dtype)) {
      if (!response_noany(d)) return -1;
    } else if (typematch(DNS_T_OPT,dtype)) {
      if (!response_noopt(d)) return -1;
    }
    if (!response_placeholder_soa(servicearpa,TTL_STATIC_NEGATIVE)) return -1;
    return 1;
  }

  return 0;
}

static int handle_specials_as_glue(struct query *z,const char *d,const char dtype[2])
{
  char ip4[IP4_LEN];
  char ip6[IP6_SANS_SCOPE_LEN];

  if (dd4(d,"",ip4) == IP4_LEN) {
    log_synthetic(d,dtype,z->level,TTL_STATIC_POSITIVE);
    if (typematch(DNS_T_A,dtype) || typematch(DNS_T_AAAA,dtype)) {
      byte_zero(ip6, sizeof ip6);
      byte_copy(ip6 + sizeof ip6 - sizeof ip4,sizeof ip4,ip4);
      ip6[10] = ip6[11] = 0xFF;
      if (z->server_count[z->level - 1] < QUERY_MAXNS_ADDR) {
        ip_make4(&z->server_addresses[z->level - 1][z->server_count[z->level - 1]],ip4);
        ++z->server_count[z->level - 1];
      }
      if (z->server_count[z->level - 1] < QUERY_MAXNS_ADDR) {
        ip_make6(&z->server_addresses[z->level - 1][z->server_count[z->level - 1]],ip6,0);
        ++z->server_count[z->level - 1];
      }
    }
    return 1;
  } else
  if (dns_domain_suffix(d,inaddrarpa)) {
    if (IP4_LEN == dd4(d,inaddrarpa,ip4)) {
      if (127 == (unsigned char)ip4[3]) {
        log_synthetic(d,dtype,z->level,TTL_STATIC_POSITIVE);
        /* No relevant RRs are synthesized for this; so hand the lower level an empty RRSet. */
        return 1;
      } else
      if (169 == (unsigned char)ip4[3] && 0xFE == (unsigned char)ip4[2]) {    /* RFC 6762 */
        log_synthetic(d,dtype,z->level,TTL_STATIC_NEGATIVE);
        /* No relevant RRs are synthesized for this; so hand the lower level an empty RRSet. */
        return 1;
      }
    }
  } else
  if (dns_domain_suffix(d,ip6arpa)) {
    if (IP6_SANS_SCOPE_LEN * 2 == dd6(d,ip6arpa,ip6)) {
      if (byte_equal("\001\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000",IP6_SANS_SCOPE_LEN,ip6)) {
        log_synthetic(d,dtype,z->level,TTL_STATIC_POSITIVE);
        /* No relevant RRs are synthesized for this; so hand the lower level an empty RRSet. */
        return 1;
      } else
      if (0xFE == (unsigned char)ip6[15] && (0x80 <= (unsigned char)ip6[14] && (unsigned char)ip6[14] < 0xA0)) {    /* RFC 6762 */
        log_synthetic(d,dtype,z->level,TTL_STATIC_NEGATIVE);
        /* No relevant RRs are synthesized for this; so hand the lower level an empty RRSet. */
        return 1;
      }
    }
  } else
  if (dns_domain_suffix(d,localhost)) {
    log_synthetic(d,dtype,z->level,TTL_STATIC_POSITIVE);
    if (IP4_LEN == dd4(d,localhost,ip4) && 127 == (unsigned char)ip4[3]) {
      if (typematch(DNS_T_A,dtype) || typematch(DNS_T_AAAA,dtype)) {
        byte_reverse(ip4, sizeof ip4); /* They are little-endian in the domain name. */
        byte_zero(ip6, sizeof ip6);
        byte_copy(ip6 + sizeof ip6 - sizeof ip4,sizeof ip4,ip4);
        ip6[10] = ip6[11] = 0xFF;
        if (z->server_count[z->level - 1] < QUERY_MAXNS_ADDR) {
          ip_make4(&z->server_addresses[z->level - 1][z->server_count[z->level - 1]],ip4);
          ++z->server_count[z->level - 1];
        }
        if (z->server_count[z->level - 1] < QUERY_MAXNS_ADDR) {
          ip_make6(&z->server_addresses[z->level - 1][z->server_count[z->level - 1]],ip6,0);
          ++z->server_count[z->level - 1];
        }
      }
    } else {
      if (typematch(DNS_T_A,dtype) || typematch(DNS_T_AAAA,dtype)) {
        if (z->server_count[z->level - 1] < QUERY_MAXNS_ADDR) {
          ip_make_loopback4(&z->server_addresses[z->level - 1][z->server_count[z->level - 1]]);
          ++z->server_count[z->level - 1];
        }
        if (z->server_count[z->level - 1] < QUERY_MAXNS_ADDR) {
          ip_make_loopback6(&z->server_addresses[z->level - 1][z->server_count[z->level - 1]]);
          ++z->server_count[z->level - 1];
        }
      }
    }
    return 1;
  } else
  if (dns_domain_suffix(d,resolverarpa)     /* RFC 9462 */
  ||  dns_domain_suffix(d,invalid)          /* RFC 6761 */
  ||  dns_domain_suffix(d,onion)            /* RFC 7686 */
  ||  dns_domain_suffix(d,local)            /* RFC 6762 */
  ||  dns_domain_suffix(d,alt)              /* RFC 9476 */
  ) {
    log_synthetic(d,dtype,z->level,TTL_STATIC_NEGATIVE);
    /* No relevant RRs are synthesized for this; so hand the lower level an empty RRSet. */
    return 1;
  } else
  if (dns_domain_suffix(d,servicearpa)) {   /* RFC 9665 */
    log_synthetic(d,dtype,z->level,TTL_STATIC_NEGATIVE);
    /* No relevant RRs are synthesized for this; so hand the lower level an empty RRSet. */
    return 1;
  }

  return 0;
}

static int save_records(const char *buf,const unsigned int len,const unsigned int posanswers,const unsigned int posauthority,const unsigned int recordsc,const char *control,const struct ip_address *whichserver)
{
  static unsigned int *recordsv = 0;
  unsigned int begin, end;
  unsigned int pos;

  if (recordsv) { alloc_free(recordsv); recordsv = 0; }

  recordsv = (unsigned int *) alloc(recordsc * sizeof *recordsv);
  if (!recordsv) goto DIE;

  /* Make an array of all resource records. */
  pos = posanswers;
  for (begin = 0;begin < recordsc;++begin) {
    char rrfixed[RRFIXED_SIZE];
    uint16 datalen;
    recordsv[begin] = pos;
    pos = dns_packet_skipname(buf,len,pos); if (!pos) goto DIE;
    pos = dns_packet_copy(buf,len,pos,rrfixed,sizeof rrfixed); if (!pos) goto DIE;
    uint16_unpack_big(rrfixed + RRFIXED_DATALEN,&datalen);
    pos += datalen;
  }

  /* Sort the array. */
  begin = end = recordsc;
  while (end > 1) {
    unsigned int p, q, r;

    if (begin > 1) { --begin; r = recordsv[begin - 1]; }
    else { r = recordsv[end - 1]; recordsv[end - 1] = recordsv[begin - 1]; --end; }

    q = begin;
    while ((p = q * 2) < end) {
      if (!smaller(buf,len,recordsv[p],recordsv[p - 1])) ++p;
      recordsv[q - 1] = recordsv[p - 1]; q = p;
    }
    if (p == end) {
      recordsv[q - 1] = recordsv[p - 1]; q = p;
    }
    while ((q > begin) && smaller(buf,len,recordsv[(p = q/2) - 1],r)) {
      recordsv[q - 1] = recordsv[p - 1]; q = p;
    }
    recordsv[q - 1] = r;
  }

  /* Cache all of the response data, which is now grouped into resource record sets. */
  for (begin = 0;begin < recordsc;begin = end) {
    char type[2];
    char rrfixed[RRFIXED_SIZE];
    uint16 datalen;
    uint32 ttl;

    end = begin + 1;

    pos = dns_packet_getname(buf,len,recordsv[begin],&t1); if (!pos) goto DIE;
    pos = dns_packet_copy(buf,len,pos,rrfixed,sizeof rrfixed); if (!pos) goto DIE;
    ttl = ttlget(rrfixed + RRFIXED_TTL);

    byte_copy(type,2,rrfixed + RRFIXED_TYPE);
    if (!internetclass(rrfixed + RRFIXED_CLASS)) continue;

    while (end < recordsc) {
      pos = dns_packet_getname(buf,len,recordsv[end],&t2); if (!pos) goto DIE;
      pos = dns_packet_copy(buf,len,pos,rrfixed,sizeof rrfixed); if (!pos) goto DIE;
      if (!dns_domain_equal(t1,t2)) break;
      if (!typematch(rrfixed + RRFIXED_TYPE,type)) break;
      if (!internetclass(rrfixed + RRFIXED_CLASS)) break;
      ++end;
    }

    /* Do not cache anything that is out-of-bailiwick. */
    if (!dns_domain_suffix(t1,control)) continue;
    /* Do not cache anything that would cross a local prune-and-graft point. */
    if (!roots_same(t1,control)) continue;

    if (typematch(type,DNS_T_ANY))
      ;
    else if (typematch(type,DNS_T_OPT))
      /* This is essntially a wire protocol extension, not a record in the distributed database.
      ** It is improper to cache it.
      */
      ;
    else if (typematch(type,DNS_T_AXFR)||typematch(type,DNS_T_IXFR))
      ;
    else if (typematch(type,DNS_T_SOA)) {
      int done_one = 0;
      save_start();
      while (begin < end) {
	char b[20];
        pos = dns_packet_skipname(buf,len,recordsv[begin]); if (!pos) goto DIE;
        pos = dns_packet_getname(buf,len,pos + RRFIXED_SIZE,&t2); if (!pos) goto DIE;
        pos = dns_packet_getname(buf,len,pos,&t3); if (!pos) goto DIE;
        pos = dns_packet_copy(buf,len,pos,b,sizeof b); if (!pos) goto DIE;
	/* It is unfortunately necessary to avoid caching the SOA RRSETs that
	** people send to us in the authority section, as they have usually
	** been modified to convey TTLs for empty RRSETs and no-such-name 
	** answers.
	*/
        if (recordsv[begin] < posauthority) {
	  log_rrsoa(whichserver,t1,t2,t3,b,ttl);
	  save_data(b,sizeof b);
	  save_data(t2,dns_domain_length(t2));
	  save_data(t3,dns_domain_length(t3));
	  done_one = 1;
	}
        ++begin;
      }
      if (done_one)
	save_finish(DNS_T_SOA,t1,ttl);
    }
    else if (typematch(type,DNS_T_CNAME)) {
      pos = dns_packet_skipname(buf,len,recordsv[end - 1]); if (!pos) goto DIE;
      pos = dns_packet_getname(buf,len,pos + RRFIXED_SIZE,&t2); if (!pos) goto DIE;
      log_rrcname(whichserver,t1,t2,ttl);
      cachegeneric(DNS_T_CNAME,t1,t2,dns_domain_length(t2),ttl);
    }
    else if (typematch(type,DNS_T_PTR)) {
      save_start();
      while (begin < end) {
        pos = dns_packet_skipname(buf,len,recordsv[begin]); if (!pos) goto DIE;
        pos = dns_packet_getname(buf,len,pos + RRFIXED_SIZE,&t2); if (!pos) goto DIE;
        log_rrptr(whichserver,t1,t2,ttl);
        save_data(t2,dns_domain_length(t2));
        ++begin;
      }
      save_finish(DNS_T_PTR,t1,ttl);
    }
    else if (typematch(type,DNS_T_NS)) {
      int done_one = 0;
      save_start();
      while (begin < end) {
        pos = dns_packet_skipname(buf,len,recordsv[begin]); if (!pos) goto DIE;
        pos = dns_packet_getname(buf,len,pos + RRFIXED_SIZE,&t2); if (!pos) goto DIE;
        /* It is unfortunately necessary to avoid caching NS RRSets that people send to us in the authority section when answering for their own domains.
        ** There is a capture effect in the DNS itself that prevents continually looked up domains from ever being re-delegated by superdomains.
        **
        ** This was originally touted as an advantage of dnscache (not re-contacting parents) and tinydns (drawing queries away from parent servers) but has over the years rather become viewed as yet another people-do-not-follow-the-correct-procedure weakness in the DNS mechanism itself.
        ** When people fail to remove no-longer-delegated-to-them domains that they once owned from their own content DNS servers, nor apply time-to-die (a tinydns feature that is supposed to be used when changing delegations), any semi-regular lookups that hit those servers prevent refetching the new superdomain delegations.
        **
        ** An explicit NS answer to an NS query is an exception to this, and will be in the answer section.
        */
        if (recordsv[begin] < posauthority || !dns_domain_equal(t1,control)) {
          log_rrns(whichserver,t1,t2,ttl);
          save_data(t2,dns_domain_length(t2));
        }
        ++begin;
      }
      if (done_one)
        save_finish(DNS_T_NS,t1,ttl);
    }
    else if (typematch(type,DNS_T_MX)) {
      save_start();
      while (begin < end) {
	char b[2];
        pos = dns_packet_skipname(buf,len,recordsv[begin]); if (!pos) goto DIE;
        pos = dns_packet_copy(buf,len,pos + RRFIXED_SIZE,b,sizeof b); if (!pos) goto DIE;
        pos = dns_packet_getname(buf,len,pos,&t2); if (!pos) goto DIE;
        log_rrmx(whichserver,t1,t2,b,ttl);
        save_data(b,sizeof b);
        save_data(t2,dns_domain_length(t2));
        ++begin;
      }
      save_finish(DNS_T_MX,t1,ttl);
    }
    else if (typematch(type,DNS_T_A)) {
      save_start();
      while (begin < end) {
        pos = dns_packet_skipname(buf,len,recordsv[begin]); if (!pos) goto DIE;
        pos = dns_packet_copy(buf,len,pos,rrfixed,sizeof rrfixed); if (!pos) goto DIE;
        if (byte_equal(rrfixed + RRFIXED_DATALEN,2,"\0\4")) {
	  char b[IP4_LEN];
          pos = dns_packet_copy(buf,len,pos,b,sizeof b); if (!pos) goto DIE;
          save_data(b,sizeof b);
          log_rr(whichserver,t1,DNS_T_A,b,sizeof b,ttl);
        }
        ++begin;
      }
      save_finish(DNS_T_A,t1,ttl);
    }
    else if (typematch(type,DNS_T_AAAA)) {
      save_start();
      while (begin < end) {
        pos = dns_packet_skipname(buf,len,recordsv[begin]); if (!pos) goto DIE;
        pos = dns_packet_copy(buf,len,pos,rrfixed,sizeof rrfixed); if (!pos) goto DIE;
        if (byte_equal(rrfixed + RRFIXED_DATALEN,2,"\0\020")) {
	  char b[IP6_SANS_SCOPE_LEN];
          pos = dns_packet_copy(buf,len,pos,b,sizeof b); if (!pos) goto DIE;
          save_data(b,sizeof b);
          log_rr(whichserver,t1,DNS_T_AAAA,b,sizeof b,ttl);
        }
        ++begin;
      }
      save_finish(DNS_T_AAAA,t1,ttl);
    }
    else {
      save_start();
      while (begin < end) {
        pos = dns_packet_skipname(buf,len,recordsv[begin]); if (!pos) goto DIE;
        pos = dns_packet_copy(buf,len,pos,rrfixed,sizeof rrfixed); if (!pos) goto DIE;
        uint16_unpack_big(rrfixed + RRFIXED_DATALEN,&datalen);
        if (datalen > len - pos) goto DIE;
        save_data(rrfixed + RRFIXED_DATALEN,2);
        save_data(buf + pos,datalen);
        log_rr(whichserver,t1,type,buf + pos,datalen,ttl);
        ++begin;
      }
      save_finish(type,t1,ttl);
    }
  }

  alloc_free(recordsv); recordsv = 0;
  return 0;

  DIE:
  alloc_free(recordsv); recordsv = 0;
  return -1;
}

static int doit(struct query *z,int state)
{
  char *buf;
  unsigned int len;
  struct ip_address *whichserver;
  char header[HEADER_SIZE];
  unsigned int rcode;
  unsigned int pos;
  unsigned int pos2;
  unsigned int posanswers;
  unsigned int posauthority;
  uint16 numanswers;
  uint16 numauthority;
  uint16 numglue;
  char *control;
  char *d;
  char *owner_name = 0 ;
  const char *dtype;
  unsigned int dlen;
  int flagempty;
  int flagreferral;
  int flagsoa;
  uint32 soattl;
  unsigned int j;
  unsigned int k;

  errno = error_io;
  if (state == 1) goto HAVEPACKET;
  if (state == -1) {
    log_servfail(z->name[z->level]);
    goto SERVFAIL;
  }


  NEWNAME:
  /* In 2025, it takes just under 300 separate NEWNAMEs just to look up www.bing.com with the original dnscache algorithm.
  ** This would be improved by not doing the glue lookups as nested higher levels that do a depth-first traversal of the gluelessness tree.
  ** It is already improved by filling in glue from the cache immediately, without resorting to a higher level restart with a NEWNAME.
  */
  if (++z->loop >= 300) {
    errno = error_loop;
    log_servfail(z->name[z->level]);
    goto DIE;
  }
  d = z->name[z->level];
  dtype = z->level ? DNS_T_A : z->type;
  dlen = dns_domain_length(d);

  log_want(d,dtype,z->level,z->loop);

  if (z->level) {
    int r;
    /* These levels are all about populating the cache (which is done in HAVEPACKET) and finding information for lower levels. */

    /* Check for special domain names handled internally.
    ** These will never have CNAMEs and will never be NXDOMAIN.
    ** They take priority over the cache, so a back-end response can never poison them.
    */
    r = handle_specials_as_glue(z,d,dtype);
    if (r > 0) goto LOWERLEVEL;
    if (r < 0) goto DIE;

    /* Now look in the cache. */
    if (dlen <= 255) {
      unsigned int any_rrset = 0;
      char *cached;
      unsigned int cachedlen;
      uint32 ttl;
      char key[257];

      byte_copy(key + 2,dlen,d);
      case_lowerb(key + 2,dlen);

      /* Check for non-existent domain names. */
      byte_copy(key,2,DNS_T_ANY);
      cached = cache_get(key,dlen + 2,&cachedlen,&ttl);
      if (cached) {
        log_cachednxdomain(d,ttl);
        goto LOWERLEVEL;
      }

      /* Chase down client-side aliases. */
      if (!typematch(DNS_T_CNAME,dtype)) {
        byte_copy(key,2,DNS_T_CNAME);
        while (dlen <= 255) {
          cached = cache_get(key,dlen + 2,&cachedlen,&ttl);
          /* A previous explicit query might have caused an empty RRSet to have been cached.
          ** Take care to ignore such a thing. 
          */
          if (cached && cachedlen) {
            log_cachedcname(d,cached,ttl);
            if (!dns_domain_copy(&z->name[z->level],cached)) goto DIE;
            d = z->name[z->level];
            dlen = dns_domain_length(d);
            byte_copy(key + 2,dlen,d);
            case_lowerb(key + 2,dlen);
            ++any_rrset;
          } else
            break;
        }
        if (any_rrset) goto NEWNAME;
      }

      /* Attempt to fulfil the lower level from the cache. */
      if (typematch(DNS_T_A,dtype) || typematch(DNS_T_AAAA,dtype)) {
        /* Always pass IPv4 and IPv6 address information together down to the lower level.
        ** This works around a design problem where we can only do one type of glue query.
        */
        byte_copy(key,2,DNS_T_A);
        cached = cache_get(key,dlen + 2,&cachedlen,&ttl);
        if (cached) {
          while (cachedlen >= IP4_LEN) {
            if (z->server_count[z->level - 1] < QUERY_MAXNS_ADDR) {
              ip_make4(&z->server_addresses[z->level - 1][z->server_count[z->level - 1]],cached);
              log_cachedglue(d,&z->server_addresses[z->level - 1][z->server_count[z->level - 1]],ttl);
              ++z->server_count[z->level - 1];
            }
            cached += IP4_LEN;
            cachedlen -= IP4_LEN;
          }
          ++any_rrset;
        }
        byte_copy(key,2,DNS_T_AAAA);
        cached = cache_get(key,dlen + 2,&cachedlen,&ttl);
        if (cached) {
          while (cachedlen >= IP6_SANS_SCOPE_LEN) {
            if (z->server_count[z->level - 1] < QUERY_MAXNS_ADDR) {
              ip_make6(&z->server_addresses[z->level - 1][z->server_count[z->level - 1]],cached,0);
              log_cachedglue(d,&z->server_addresses[z->level - 1][z->server_count[z->level - 1]],ttl);
              ++z->server_count[z->level - 1];
            }
            cached += IP6_SANS_SCOPE_LEN;
            cachedlen -= IP6_SANS_SCOPE_LEN;
          }
          ++any_rrset;
        }
      }
      else if (typematch(DNS_T_ANY,dtype) || typematch(DNS_T_OPT,dtype) || typematch(DNS_T_AXFR,dtype) || typematch(DNS_T_IXFR,dtype)) {
        /* These are either synthesized or forbidden.
        ** So always return to the lower level without checking the cache.
        */
        ++any_rrset;
      }
      else {
        /* If it is in the cache, the lower level can get it from the cache.
        ** Otherwise we need to kick off an actual back-end transaction.
        */
        byte_copy(key,2,dtype);
        cached = cache_get(key,dlen + 2,&cachedlen,&ttl);
        if (cached)
          ++any_rrset;
      }

      if (any_rrset) goto LOWERLEVEL;
    }
  } else {
    int r;
    /* This level is all about answering clients from the cache. */

    /* Check for special domain names handled internally.
    ** These will never have CNAMEs and will never be NXDOMAIN.
    ** They take priority over the cache, so a back-end response can never poison them.
    */
    r = handle_specials(z,d,dtype);
    if (r > 0) {
      cleanup(z);
      log_stats();
      return r;
    }
    if (r < 0) goto DIE;

    /* Now look in the cache. */
    if (dlen <= 255) {
      unsigned int any_rrset = 0;
      char *cached;
      unsigned int cachedlen;
      uint32 ttl;
      char key[257];

      byte_copy(key + 2,dlen,d);
      case_lowerb(key + 2,dlen);

      /* Check for non-existent domain names. */
      byte_copy(key,2,DNS_T_ANY);
      cached = cache_get(key,dlen + 2,&cachedlen,&ttl);
      if (cached) {
        log_cachednxdomain(d,ttl);
        goto NXDOMAIN;
      }

      /* Chase down client-side aliases. */
      if (!typematch(DNS_T_CNAME,dtype)) {
        byte_copy(key,2,DNS_T_CNAME);
        while (dlen <= 255) {
          cached = cache_get(key,dlen + 2,&cachedlen,&ttl);
          /* A previous explicit query might have caused an empty RRSet to have been cached.
          ** Take care to ignore such a thing. 
          */
          if (cached && cachedlen) {
            log_cachedcname(d,cached,ttl);
            if (!move_name_to_alias(z,ttl)) goto DIE;
            if (!dns_domain_copy(&z->name[z->level],cached)) goto DIE;
            d = z->name[z->level];
            dlen = dns_domain_length(d);
            byte_copy(key + 2,dlen,d);
            case_lowerb(key + 2,dlen);
            ++any_rrset;
          } else
            break;
        }
      }
      if (any_rrset) goto NEWNAME;

      /* Attempt to answer the client from the cache.
      ** Synthesized responses to ANY or OPT must not override NXDOMAIN or CNAME.
      */
      byte_copy(key,2,dtype);
      if (typematch(DNS_T_ANY,dtype)) {
        log_synthetic(d,dtype,z->level,TTL_POSITIVE);
        if (!rqa(z)) goto DIE;
        if (!response_noany(d)) goto DIE;
        cleanup(z);
        return 1;
      }
      else if (typematch(DNS_T_OPT,dtype)) {
        log_synthetic(d,dtype,z->level,TTL_POSITIVE);
        if (!rqa(z)) goto DIE;
        if (!response_noopt(d)) goto DIE;
        cleanup(z);
        return 1;
      }
      else if (typematch(DNS_T_AXFR,dtype)||typematch(DNS_T_IXFR,dtype)) {
        /* Should have been rejected at the query start level and never get here. */
        log_synthetic(d,dtype,z->level,TTL_POSITIVE);
        if (!rqa(z)) goto DIE;
        if (!response_noaxfr(d)) goto DIE;
        cleanup(z);
        return 1;
      }
      else if (typematch(DNS_T_CNAME,dtype)) {
        cached = cache_get(key,dlen + 2,&cachedlen,&ttl);
        /* A previous explicit query might have caused an empty RRSet to have been cached.
        ** Take care to ignore such a thing. 
        */
        if (cached && cachedlen) {
          log_cachedanswer(d,DNS_T_CNAME,ttl);
          if (!rqa(z)) goto DIE;
          if (!response_cname(z->name[0],cached,ttl)) goto DIE;
          cleanup(z);
          return 1;
        }
      }
      else if (typematch(DNS_T_SOA,dtype)) {
        cached = cache_get(key,dlen + 2,&cachedlen,&ttl);
        if (cached) {
          char b[20];
          log_cachedanswer(d,DNS_T_SOA,ttl);
          if (!rqa(z)) goto DIE;
          pos = 0;
          while ((pos = dns_packet_copy(cached,cachedlen,pos,b,sizeof b))) {
            pos = dns_packet_getname(cached,cachedlen,pos,&t2);
            if (!pos) break;
            pos = dns_packet_getname(cached,cachedlen,pos,&t3);
            if (!pos) break;
            if (!response_rstart(d,DNS_T_SOA,ttl)) goto DIE;
            if (!response_addname(t2)) goto DIE;
            if (!response_addname(t3)) goto DIE;
            if (!response_addbytes(b,sizeof b)) goto DIE;
            response_rfinish(RESPONSE_ANSWER);
          }
          cleanup(z);
          return 1;
        }
      }
      else if (typematch(DNS_T_NS,dtype)) {
        cached = cache_get(key,dlen + 2,&cachedlen,&ttl);
        if (cached) {
          log_cachedanswer(d,DNS_T_NS,ttl);
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
      else if (typematch(DNS_T_PTR,dtype)) {
        cached = cache_get(key,dlen + 2,&cachedlen,&ttl);
        if (cached) {
          log_cachedanswer(d,DNS_T_PTR,ttl);
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
      else if (typematch(DNS_T_MX,dtype)) {
        cached = cache_get(key,dlen + 2,&cachedlen,&ttl);
        if (cached) {
          char b[2];
          log_cachedanswer(d,DNS_T_MX,ttl);
          if (!rqa(z)) goto DIE;
          pos = 0;
          while ((pos = dns_packet_copy(cached,cachedlen,pos,b,sizeof b))) {
            pos = dns_packet_getname(cached,cachedlen,pos,&t2);
            if (!pos) break;
            if (!response_rstart(d,DNS_T_MX,ttl)) goto DIE;
            if (!response_addbytes(b,sizeof b)) goto DIE;
            if (!response_addname(t2)) goto DIE;
            response_rfinish(RESPONSE_ANSWER);
          }
          cleanup(z);
          return 1;
        }
      }
      else if (typematch(DNS_T_A,dtype)) {
        cached = cache_get(key,dlen + 2,&cachedlen,&ttl);
        if (cached) {
          log_cachedanswer(d,DNS_T_A,ttl);
          if (!rqa(z)) goto DIE;
          while (cachedlen >= IP4_LEN) {
            if (!response_rstart(d,DNS_T_A,ttl)) goto DIE;
            if (!response_addbytes(cached,IP4_LEN)) goto DIE;
            response_rfinish(RESPONSE_ANSWER);
            cached += IP4_LEN;
            cachedlen -= IP4_LEN;
          }
          cleanup(z);
          return 1;
        }
      }
      else if (typematch(DNS_T_AAAA,dtype)) {
        cached = cache_get(key,dlen + 2,&cachedlen,&ttl);
        if (cached) {
          log_cachedanswer(d,DNS_T_AAAA,ttl);
          if (!rqa(z)) goto DIE;
          while (cachedlen >= IP6_SANS_SCOPE_LEN) {
            if (!response_rstart(d,DNS_T_AAAA,ttl)) goto DIE;
            if (!response_addbytes(cached,IP6_SANS_SCOPE_LEN)) goto DIE;
            response_rfinish(RESPONSE_ANSWER);
            cached += IP6_SANS_SCOPE_LEN;
            cachedlen -= IP6_SANS_SCOPE_LEN;
          }
          cleanup(z);
          return 1;
        }
      }
      else {
        cached = cache_get(key,dlen + 2,&cachedlen,&ttl);
        if (cached) {
          log_cachedanswer(d,dtype,ttl);
          if (!rqa(z)) goto DIE;
          while (cachedlen >= 2) {
            uint16 datalen;
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
  }

  /* Find the root IP addresses or the nameserver names to begin at. */
  cleanup_nameserver_names(z,z->level);
  reset_nameserver_addresses(z,z->level);
  for (;;) {
    if (roots(z->server_addresses[z->level],QUERY_MAXNS_ADDR,&z->server_count[z->level],d)) {
      z->control[z->level] = d;
      log_root(z->name[z->level],dtype,z->control[z->level],z->level);
      goto HAVENSADDR;
    }

    if (!flagforwardonly && (z->level < QUERY_MIN_USE_ROOTS_LEVEL))
      if (dlen < 255) {
        char *cached;
        unsigned int cachedlen;
        uint32 ttl;
        char key[257];

        byte_copy(key,2,DNS_T_NS);
        byte_copy(key + 2,dlen,d);
        case_lowerb(key + 2,dlen);
        cached = cache_get(key,dlen + 2,&cachedlen,&ttl);
        if (cached && cachedlen) {
	  z->control[z->level] = d;
          pos = 0;
          j = 0;
          while ((pos = dns_packet_getname(cached,cachedlen,pos,&t1))) {
	    log_cachedns(d,t1,ttl);
            if (j < QUERY_MAXNS)
              if (!dns_domain_copy(&z->ns[z->level][j++],t1)) goto DIE;
	  }
          goto HAVENS;
        }
      }

    if (!*d) goto DIE;
    j = 1 + (unsigned int) (unsigned char) *d;
    dlen -= j;
    d += j;
  }


  HAVENS:
  reset_nameserver_addresses(z,z->level);
  HAVENSPARTIAL:
  for (j = 0;j < QUERY_MAXNS;++j)
    if (z->ns[z->level][j]) {
      const char *nd = z->ns[z->level][j];
      unsigned int ndlen = dns_domain_length(nd);
      unsigned int any_rrset = 0;

      if (ndlen < 255) {
        char *cached;
        unsigned int cachedlen;
        uint32 ttl;
        char key[257];

        byte_copy(key + 2,ndlen,nd);
        case_lowerb(key + 2,ndlen);

        byte_copy(key,2,DNS_T_A);
        cached = cache_get(key,ndlen + 2,&cachedlen,&ttl);
        if (cached) {
          while (cachedlen >= IP4_LEN) {
            if (z->server_count[z->level] < QUERY_MAXNS_ADDR) {
              ip_make4(&z->server_addresses[z->level][z->server_count[z->level]],cached);
              log_cachedglue(nd,&z->server_addresses[z->level][z->server_count[z->level]],ttl);
              ++z->server_count[z->level];
            }
            cached += IP4_LEN;
            cachedlen -= IP4_LEN;
          }
          ++any_rrset;
        }
        byte_copy(key,2,DNS_T_AAAA);
        cached = cache_get(key,ndlen + 2,&cachedlen,&ttl);
        if (cached) {
          while (cachedlen >= IP6_SANS_SCOPE_LEN) {
            if (z->server_count[z->level] < QUERY_MAXNS_ADDR) {
              ip_make6(&z->server_addresses[z->level][z->server_count[z->level]],cached,0);
              log_cachedglue(nd,&z->server_addresses[z->level][z->server_count[z->level]],ttl);
              ++z->server_count[z->level];
            }
            cached += IP6_SANS_SCOPE_LEN;
            cachedlen -= IP6_SANS_SCOPE_LEN;
          }
          ++any_rrset;
        }
      }
      if (!any_rrset)
        if (z->level + 1 < QUERY_MAXLEVEL) {
          if (!dns_domain_copy(&z->name[z->level + 1],z->ns[z->level][j])) goto DIE;
          dns_domain_free(&z->ns[z->level][j]);
          ++z->level;
          cleanup_nameserver_names(z,z->level);
          reset_nameserver_addresses(z,z->level);
          goto NEWNAME;
        }
      dns_domain_free(&z->ns[z->level][j]);
    }

  HAVENSADDR:
  k = 0;
  for (j = 0;j < z->server_count[z->level];j += 1)
    if (!ip_is_unassigned(z->server_addresses[z->level] + j))
      ++k;
  if (0 == k) {
    log_no_servers(z->name[z->level]);
    goto SERVFAIL;
  }

  dns_sortip(z->server_addresses[z->level],z->server_count[z->level]);
  dtype = z->level ? DNS_T_A : z->type;
  log_tx(z->name[z->level],dtype,z->control[z->level],z->server_addresses[z->level],z->level);
  if (dns_transmit_start(&z->dt,z->server_addresses[z->level],z->server_count[z->level],53,recursiondesired,z->name[z->level],dtype,&z->localip) == -1) goto DIE;
  return 0;


  LOWERLEVEL:
  dns_domain_free(&z->name[z->level]);
  cleanup_nameserver_names(z,z->level);
  reset_nameserver_addresses(z,z->level);
  --z->level;
  goto HAVENSPARTIAL;


  HAVEPACKET:
  if (++z->loop == 100) goto DIE;
  buf = z->dt.packet;
  len = z->dt.packetlen;

  whichserver = z->dt.server_addresses + z->dt.current_server;
  control = z->control[z->level];
  d = z->name[z->level];
  dtype = z->level ? DNS_T_A : z->type;

  pos = dns_packet_copy(buf,len,0,header,sizeof header); if (!pos) goto DIE;
  pos = dns_packet_skipname(buf,len,pos); if (!pos) goto DIE;
  pos += 4;
  posanswers = pos;

  uint16_unpack_big(header + HEADER_ANSWER,&numanswers);
  uint16_unpack_big(header + HEADER_AUTHORITY,&numauthority);
  uint16_unpack_big(header + HEADER_ADDITIONAL,&numglue);

  rcode = header[3] & 15;
  if (rcode && (rcode != 3)) goto DIE; /* impossible; see irrelevant() */

  flagempty = 1;
  flagreferral = 0;
  flagsoa = 0;
  soattl = 0;
  if (!dns_domain_copy(&owner_name,d)) goto DIE;
  /* This code assumes that the CNAME chain is presented in the correct 
  ** order.  The example algorithm in RFC 1034 will actually result in this
  ** being the case, but the words do not require it to be so.
  */
  for (j = 0;j < numanswers;++j) {
    char rrfixed[RRFIXED_SIZE];
    uint16 datalen;
    pos = dns_packet_getname(buf,len,pos,&t1); if (!pos) goto DIE;
    pos = dns_packet_copy(buf,len,pos,rrfixed,sizeof rrfixed); if (!pos) goto DIE;

    if (internetclass(rrfixed + RRFIXED_CLASS)) { /* should always be true */
      if (dns_domain_equal(t1,owner_name)) {
        if (typematch(rrfixed + RRFIXED_TYPE,dtype))
          flagempty = 0;
        else if (typematch(rrfixed + RRFIXED_TYPE,DNS_T_CNAME)) {
          if (!dns_packet_getname(buf,len,pos,&owner_name)) goto DIE;
        }
      }
    }
  
    uint16_unpack_big(rrfixed + RRFIXED_DATALEN,&datalen);
    pos += datalen;
  }
  dns_domain_free(&owner_name) ;
  posauthority = pos;

  /* Scan the authority section for empty RRset indicators and referrals. */
  for (j = 0;j < numauthority;++j) {
    char rrfixed[RRFIXED_SIZE];
    uint16 datalen;
    pos = dns_packet_getname(buf,len,pos,&t1); if (!pos) goto DIE;
    pos = dns_packet_copy(buf,len,pos,rrfixed,sizeof rrfixed); if (!pos) goto DIE;
    if (internetclass(rrfixed + RRFIXED_CLASS)) { /* should always be true */
      if (typematch(rrfixed + RRFIXED_TYPE,DNS_T_SOA)) {
        flagsoa = 1;
        soattl = ttlget(rrfixed + RRFIXED_TTL);
        if (soattl > TTL_SOA_MAX) soattl = TTL_SOA_MAX;
      }
      else if (typematch(rrfixed + RRFIXED_TYPE,DNS_T_NS)) {
        flagreferral = 1;
        if (!dns_domain_copy(&referral,t1)) goto DIE;
      }
    }

    uint16_unpack_big(rrfixed + RRFIXED_DATALEN,&datalen);
    pos += datalen;
  }

  if (0 > save_records(buf,len,posanswers,posauthority,numanswers+numauthority+numglue,control,whichserver)) goto DIE;

  if (!typematch(DNS_T_CNAME,dtype)) {
    /* This code assumes that the CNAME chain is presented in the correct 
    ** order.  The example algorithm in RFC 1034 will actually result in this
    ** being the case, but the words do not require it to be so.
    */
    pos = posanswers;
    for (j = 0;j < numanswers;++j) {
      char rrfixed[RRFIXED_SIZE];
      uint16 datalen;

      pos = dns_packet_getname(buf,len,pos,&t1); if (!pos) goto DIE;
      pos = dns_packet_copy(buf,len,pos,rrfixed,sizeof rrfixed); if (!pos) goto DIE;
      if (internetclass(rrfixed + RRFIXED_CLASS)) { /* should always be true */
        if (typematch(rrfixed + RRFIXED_TYPE,DNS_T_CNAME))
          if (dns_domain_equal(t1,d)) {
	    if (z->level == 0) {
              uint32 ttl = ttlget(rrfixed + RRFIXED_TTL);
	      if (!move_name_to_alias(z,ttl)) goto DIE ;
	    }
	    if (!dns_packet_getname(buf,len,pos,&z->name[z->level])) goto DIE;
	    d = z->name[z->level];
	    if (!dns_domain_suffix(d,control) || !roots_same(d,control))
	      goto NEWNAME ;  /* Cannot trust the chain further - restart using current name */
	  }
      }

      uint16_unpack_big(rrfixed + RRFIXED_DATALEN,&datalen);
      pos += datalen;
    }
  }

  /* A "no such name" error applies to the end of any CNAME chain, not to the start. */
  if (rcode == 3) {
    log_nxdomain(whichserver,d,soattl);
    cachegeneric(DNS_T_ANY,d,"",0,soattl);
    if (z->level) goto LOWERLEVEL;

  NXDOMAIN:
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
  if (!rcode && flagempty && flagreferral && !flagsoa)
    if (dns_domain_equal(referral,control) || !dns_domain_suffix(referral,control)) {
      log_lame(whichserver,control,referral);
      ip_make_unassigned(whichserver);
      goto HAVENS;
    }

  /* Cache an empty set positive answer. */
  if (!rcode && flagempty && flagsoa)
    /* Don't save empty RRSets for those types that we use as special markers. */
    if (!typematch(DNS_T_ANY,dtype) && !typematch(DNS_T_OPT,dtype) && !typematch(DNS_T_AXFR,dtype) && !typematch(DNS_T_IXFR,dtype)) {
      save_start();
      save_finish(dtype,d,soattl);
      log_nodata(whichserver,d,dtype,soattl);
    }

  log_stats();


  /* Check for a complete response, or a negative answer; and either go down a level or send the answer to the client. */
  if (!flagempty || flagsoa || !flagreferral) {
    if (z->level) {
      pos = posanswers;
      for (j = 0;j < numanswers;++j) {
        char rrfixed[RRFIXED_SIZE];
        uint16 datalen;

        pos = dns_packet_getname(buf,len,pos,&t1); if (!pos) goto DIE;
        pos = dns_packet_copy(buf,len,pos,rrfixed,sizeof rrfixed); if (!pos) goto DIE;
        uint16_unpack_big(rrfixed + RRFIXED_DATALEN,&datalen);
        if (internetclass(rrfixed + RRFIXED_CLASS)) { /* should always be true */
          if (dns_domain_equal(t1,d)) {
	    if (typematch(rrfixed + RRFIXED_TYPE,DNS_T_A)) {
              if (datalen == IP4_LEN)
		if (z->server_count[z->level - 1] < QUERY_MAXNS_ADDR) {
		  char b[IP4_LEN];
		  if (!dns_packet_copy(buf,len,pos,b,sizeof b)) goto DIE;
		  ip_make4(&z->server_addresses[z->level - 1][z->server_count[z->level - 1]],b);
		  ++z->server_count[z->level - 1];
		}
	    } else if (typematch(rrfixed + RRFIXED_TYPE,DNS_T_AAAA)) {
              if (IP6_SANS_SCOPE_LEN == datalen)
		if (z->server_count[z->level - 1] < QUERY_MAXNS_ADDR) {
		  char b[IP6_SANS_SCOPE_LEN];
		  if (!dns_packet_copy(buf,len,pos,b,sizeof b)) goto DIE;
		  ip_make6(&z->server_addresses[z->level - 1][z->server_count[z->level - 1]],b,0);
		  ++z->server_count[z->level - 1];
		}
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
      char rrfixed[RRFIXED_SIZE];
      uint16 datalen;

      pos = dns_packet_getname(buf,len,pos,&t1); if (!pos) goto DIE;
      pos = dns_packet_copy(buf,len,pos,rrfixed,sizeof rrfixed); if (!pos) goto DIE;
      uint16_unpack_big(rrfixed + RRFIXED_DATALEN,&datalen);
      if (internetclass(rrfixed + RRFIXED_CLASS)) /* should always be true */
        if (dns_domain_equal(t1,d))
          if (typematch(rrfixed + RRFIXED_TYPE,dtype)) {
            uint32 ttl = ttlget(rrfixed + RRFIXED_TTL);
            if (!response_rstart(t1,rrfixed + RRFIXED_TYPE,ttl)) goto DIE;
  
            if (typematch(rrfixed + RRFIXED_TYPE,DNS_T_NS) || typematch(rrfixed + RRFIXED_TYPE,DNS_T_CNAME) || typematch(rrfixed + RRFIXED_TYPE,DNS_T_PTR)) {
              if (!dns_packet_getname(buf,len,pos,&t2)) goto DIE;
              if (!response_addname(t2)) goto DIE;
            }
            else if (typematch(rrfixed + RRFIXED_TYPE,DNS_T_MX)) {
	      char b[2];
              pos2 = dns_packet_copy(buf,len,pos,b,sizeof b); if (!pos2) goto DIE;
              if (!response_addbytes(b,sizeof b)) goto DIE;
              if (!dns_packet_getname(buf,len,pos2,&t2)) goto DIE;
              if (!response_addname(t2)) goto DIE;
            }
            else if (typematch(rrfixed + RRFIXED_TYPE,DNS_T_SOA)) {
	      char b[20];
              pos2 = dns_packet_getname(buf,len,pos,&t2); if (!pos2) goto DIE;
              if (!response_addname(t2)) goto DIE;
              pos2 = dns_packet_getname(buf,len,pos2,&t3); if (!pos2) goto DIE;
              if (!response_addname(t3)) goto DIE;
              pos2 = dns_packet_copy(buf,len,pos2,b,sizeof b); if (!pos2) goto DIE;
              if (!response_addbytes(b,sizeof b)) goto DIE;
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
      log_ignore_referral(whichserver,control,referral,z->level);
      ip_make_unassigned(whichserver);
      goto HAVENS;
  }

  log_referral(whichserver,control,referral,z->level);
  control = d + dns_domain_suffixpos(d,referral);
  z->control[z->level] = control;
  cleanup_nameserver_names(z,z->level);

  k = 0;
  pos = posauthority;
  for (j = 0;j < numauthority;++j) {
    char rrfixed[RRFIXED_SIZE];
    uint16 datalen;
    pos = dns_packet_getname(buf,len,pos,&t1); if (!pos) goto DIE;
    pos = dns_packet_copy(buf,len,pos,rrfixed,sizeof rrfixed); if (!pos) goto DIE;
    uint16_unpack_big(rrfixed + RRFIXED_DATALEN,&datalen);
    if (typematch(rrfixed + RRFIXED_TYPE,DNS_T_NS)) /* should always be true */
      if (internetclass(rrfixed + RRFIXED_CLASS)) /* should always be true */
        if (dns_domain_equal(referral,t1)) /* should always be true */
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
  dns_domain_free(&owner_name) ;
  return -1;
}

int query_start(struct query *z,char *dn,char type[2],char class[2],const struct ip_address * localip)
{
  if (typematch(type,DNS_T_AXFR)||typematch(type,DNS_T_IXFR)) { errno = error_perm; return -1; }

  cleanup(z);
  z->level = 0;
  z->loop = 0;

  if (!dns_domain_copy(&z->name[0],dn)) return -1;
  byte_copy(z->type,2,type);
  byte_copy(z->class,2,class);
  z->localip = *localip;

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
