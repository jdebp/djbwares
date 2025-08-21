#include "byte.h"
#include "uint32.h"
#include "dns_constants.h"
#include "dns_server.h"
#include "dns_domain.h"
#include "dns_nd.h"
#include "dd.h"
#include "response.h"

const char *fatal = "walldns: fatal: ";
const char *starting = "starting walldns\n";

void initialize(void)
{
}

static int typematch(const char rtype[2],const char qtype[2])
{
  return byte_equal(qtype,2,rtype);
}

static const char ipv4onlyarpa[] = "\010ipv4only\004arpa";
static const char localhost[] = "\011localhost";
static const char ip6arpa[] = "\003ip6\004arpa";
static const char inaddrarpa[] = "\007in-addr\004arpa";
static const char servicearpa[] = "\007service\004arpa";

int respond(const char *q,const char qtype[2],unsigned int max,const struct ip_address * ipremote)
{
  char ip4[IP4_LEN];
  char ip6[IP6_LEN];

  (void)ipremote; /* Silence a compiler warning. */
  (void)max; /* Silence a compiler warning. */

  /* Note that these are subtly different to the fixed built-in responses that proxy DNS servers or DNS client libraries should/must give. */

  if (dd4(q,"",ip4) == IP4_LEN) {
    if (typematch(DNS_T_ANY,qtype)) {
      if (!response_noany(q)) return 0;
      response_placeholder_soa("",TTL_STATIC_NEGATIVE);
    } else if (typematch(DNS_T_OPT,qtype)) {
      if (!response_noopt(q)) return 0;
      response_placeholder_soa("",TTL_STATIC_NEGATIVE);
    } else if (typematch(DNS_T_A,qtype)) {
      if (!response_rstart(q,DNS_T_A,TTL_STATIC_POSITIVE)) return 0;
      if (!response_addbytes(ip4,sizeof ip4)) return 0;
      response_rfinish(RESPONSE_ANSWER);
    } else
      response_placeholder_soa("",TTL_STATIC_NEGATIVE);
    return 1;
  } else
  if (dns_domain_suffix(q,inaddrarpa)) {
    if (IP4_LEN != dd4(q,inaddrarpa,ip4)) {
      response_placeholder_soa(inaddrarpa,TTL_STATIC_NEGATIVE);
      response_nxdomain();
    } else if (typematch(DNS_T_ANY,qtype)) {
      if (!response_noany(q)) return 0;
      response_placeholder_soa(inaddrarpa,TTL_STATIC_NEGATIVE);
    } else if (typematch(DNS_T_OPT,qtype)) {
      if (!response_noopt(q)) return 0;
      response_placeholder_soa(inaddrarpa,TTL_STATIC_NEGATIVE);
    } else if (typematch(DNS_T_PTR,qtype)) {
      if (!response_rstart(q,qtype,TTL_STATIC_POSITIVE)) return 0;
      if (127 == (unsigned char)ip4[3]) {
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
      } else
      if (192 == (unsigned char)ip4[3]
      &&  0 == (unsigned char)ip4[2]
      &&  0 == (unsigned char)ip4[1]
      &&  (170 == (unsigned char)ip4[0] || 171 == (unsigned char)ip4[0])
      ) {  /* RFC 8880 */
        if (!response_addname(ipv4onlyarpa)) return 0;
      } else {
        if (!response_addname(q)) return 0; /* original opaque wall */
      }
      response_rfinish(RESPONSE_ANSWER);
    } else if (typematch(DNS_T_A,qtype)) {  /* original opaque wall */
      if (!response_rstart(q,qtype,TTL_STATIC_POSITIVE)) return 0;
      byte_reverse(ip4, sizeof ip4); /* They are little-endian in the domain name. */
      if (!response_addbytes(ip4,sizeof ip4)) return 0;
      response_rfinish(RESPONSE_ANSWER);
    } else
      response_placeholder_soa(inaddrarpa,TTL_STATIC_NEGATIVE);
    return 1;
  } else
  if (dns_domain_suffix(q,ip6arpa)) {
    if (IP6_SANS_SCOPE_LEN * 2 != dd6(q,ip6arpa,ip6)) {
      response_placeholder_soa(ip6arpa,TTL_STATIC_NEGATIVE);
      response_nxdomain();
    } else if (typematch(DNS_T_ANY,qtype)) {
      if (!response_noany(q)) return 0;
      response_placeholder_soa(ip6arpa,TTL_STATIC_NEGATIVE);
    } else if (typematch(DNS_T_OPT,qtype)) {
      if (!response_noopt(q)) return 0;
      response_placeholder_soa(ip6arpa,TTL_STATIC_NEGATIVE);
    } else if (typematch(DNS_T_PTR,qtype)) {
      if (!response_rstart(q,qtype,TTL_STATIC_POSITIVE)) return 0;
        if (byte_equal("\001\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000",IP6_SANS_SCOPE_LEN,ip6)) {
          if (!response_addname(localhost)) return 0;
        } else {
        if (!response_addname(q)) return 0;
        }
      response_rfinish(RESPONSE_ANSWER);
    } else if (typematch(DNS_T_AAAA,qtype)) {
      if (!response_rstart(q,qtype,TTL_STATIC_POSITIVE)) return 0;
      byte_reverse(ip6, sizeof ip6); /* They are little-endian in the domain name. */
      if (!response_addbytes(ip6,sizeof ip6)) return 0;
      response_rfinish(RESPONSE_ANSWER);
    } else
      response_placeholder_soa(ip6arpa,TTL_STATIC_NEGATIVE);
    return 1;
  } else
  if (dns_domain_suffix(q,localhost)) {             /* RFC 6761 */
    if (typematch(DNS_T_ANY,qtype)) {
      if (!response_noany(q)) return 0;
      response_placeholder_soa(localhost,TTL_STATIC_NEGATIVE);
    } else if (typematch(DNS_T_OPT,qtype)) {
      if (!response_noopt(q)) return 0;
      response_placeholder_soa(localhost,TTL_STATIC_NEGATIVE);
    } else if (typematch(DNS_T_A,qtype)) {
      if (!response_rstart(q,qtype,TTL_STATIC_POSITIVE)) return 0;
        if (!response_addbytes("\177\000\000\001",IP4_LEN)) return 0;
      response_rfinish(RESPONSE_ANSWER);
    } else if (typematch(DNS_T_AAAA,qtype)) {
        if (!response_rstart(q,qtype,TTL_STATIC_POSITIVE)) return 0;
        if (!response_addbytes("\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\001",IP6_SANS_SCOPE_LEN)) return 0;
        response_rfinish(RESPONSE_ANSWER);
    } else
      response_placeholder_soa(localhost,TTL_STATIC_NEGATIVE);
    return 1;
  } else
  if (dns_domain_equal(q,ipv4onlyarpa)) {           /* RFC 8880 */
    if (typematch(DNS_T_ANY,qtype)) {
      if (!response_noany(q)) return 0;
      response_placeholder_soa(ipv4onlyarpa,TTL_STATIC_NEGATIVE);
    } else if (typematch(DNS_T_OPT,qtype)) {
      if (!response_noopt(q)) return 0;
      response_placeholder_soa(ipv4onlyarpa,TTL_STATIC_NEGATIVE);
    } else if (typematch(DNS_T_A,qtype)) {
        if (!response_rstart(q,qtype,TTL_STATIC_POSITIVE)) return 0;
        if (!response_addbytes("\300\000\000\252",IP4_LEN)) return 0;
        response_rfinish(RESPONSE_ANSWER);
        if (!response_rstart(q,qtype,TTL_STATIC_POSITIVE)) return 0;
        if (!response_addbytes("\300\000\000\253",IP4_LEN)) return 0;
        response_rfinish(RESPONSE_ANSWER);
    } else
      response_placeholder_soa(ipv4onlyarpa,TTL_STATIC_NEGATIVE);
    return 1;
  } else
  if (dns_domain_suffix(q,"\004home\004arpa")       /* RFC 8375 */
  ||  dns_domain_suffix(q,"\007example")            /* RFC 6761 */
  ||  dns_domain_suffix(q,"\007example\003org")     /* RFC 6761 */
  ||  dns_domain_suffix(q,"\007example\003net")     /* RFC 6761 */
  ||  dns_domain_suffix(q,"\007example\003com")     /* RFC 6761 */
  ) {
    return 0;
  } else
  if (dns_domain_suffix(q,"\004test")               /* RFC 6761 */
  ||  dns_domain_suffix(q,"\007invalid")            /* RFC 6761 */
  ||  dns_domain_suffix(q,"\003alt")                /* RFC 9476 */
  ||  dns_domain_suffix(q,"\005onion")              /* RFC 7686 */
  ||  dns_domain_suffix(q,"\005local")              /* RFC 6762 */
  ||  dns_domain_suffix(q,ipv4onlyarpa)             /* RFC 8880 */
  ||  dns_domain_suffix(q,"\010resolver\004arpa")   /* RFC 9462 */
  ||  dns_domain_suffix(q,"\0066tisch\004arpa")     /* RFC 9031 */
  ||  dns_domain_suffix(q,"\010eap-noob\004arpa")   /* RFC 9140 */
  ) {
    response_placeholder_soa(q,TTL_STATIC_NEGATIVE);
    response_nxdomain();
    return 1;
  } else
  if (dns_domain_suffix(q,servicearpa)) { /* RFC 9665 */
    if (!dns_domain_equal(q,servicearpa)
    &&  !dns_domain_equal(q,"\007default\007service\004arpa")
    ) {
      response_nxdomain();
    } else if (typematch(DNS_T_ANY,qtype)) {
      if (!response_noany(q)) return 0;
    } else if (typematch(DNS_T_OPT,qtype)) {
      if (!response_noopt(q)) return 0;
    }
    response_placeholder_soa(servicearpa,TTL_STATIC_NEGATIVE);
    return 1;
  }

  return 0;
}
