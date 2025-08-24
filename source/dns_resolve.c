#include "iopause.h"
#include "taia.h"
#include "byte.h"
#include "dns_transmit.h"
#include "dns_resolve.h"
#include "dns_constants.h"
#include "dns_domain.h"
#include "dns_packet.h"
#include "dns_nd.h"
#include "dd.h"
#include "response.h"

/* There is no restriction on the qtype at this layer; as one could be using unusual qtypes for debugging purposes.
** The qtype restrictions are in the various dns_xx() libraries layered on top of dns_resolve.
** They simply only send specific query types in the first place.
*/

struct dns_transmit dns_resolve_tx = {};

int dns_resolve_servers_nospecials(const char *q,const char qtype[2],const struct ip_address server_list[],unsigned int server_count,unsigned int port,int flagrecursive)
{
  struct taia stamp;
  struct taia deadline;
  iopause_fd x[1];
  int r;
  struct ip_address iplocal = IP_ADDRESS_INIT;

  if (dns_transmit_start(&dns_resolve_tx,server_list,server_count,port,flagrecursive,q,qtype,&iplocal) == -1) return -1;

  for (;;) {
    taia_now(&stamp);
    taia_uint(&deadline,120);
    taia_add(&deadline,&deadline,&stamp);
    dns_transmit_io(&dns_resolve_tx,x,&deadline);
    iopause(x,1,&deadline,&stamp);
    r = dns_transmit_get(&dns_resolve_tx,x,&stamp);
    if (r == -1) return -1;
    if (r == 1) return 0;
  }
}

int dns_resolve_nospecials(const char *q,const char qtype[2])
{
  struct ip_address server_list[16];
  unsigned int server_count = sizeof server_list/sizeof *server_list;
  unsigned int port;

  if (dns_resolvconfip(q,server_list,server_count,&server_count,&port) == -1) return -1;
  return dns_resolve_servers_nospecials(q,qtype,server_list,server_count,port,1);
}

static const char localhost[] = "\011localhost";
static const char inaddrarpa[] = "\007in-addr\004arpa";
static const char ipv4onlyarpa[] = "\010ipv4only\004arpa";

/* The set of fixed built-in responses that DNS client libraries should/must give.
** Note that this is subtly different to the fixed built-in responses that proxy or content DNS servers should/must give.
*/
static int handle_specials(const char *q,const char qtype[2],unsigned int server_count)
{
  char ip4[IP4_LEN];

  if (dns_domain_suffix(q,"\005onion") && !server_count) {      /* RFC 7686 */
    if (!response_query(q,qtype,DNS_C_IN)) return -1;
    response_nxdomain();
    return dns_transmit_set(&dns_resolve_tx,response,response_len);
  } else
  if (dns_domain_suffix(q,"\007invalid")) { /* RFC 6761 */
    if (!response_query(q,qtype,DNS_C_IN)) return -1;
    response_nxdomain();
    return dns_transmit_set(&dns_resolve_tx,response,response_len);
  } else
  if (dns_domain_suffix(q,localhost)) {     /* RFC 6761 */
    if (!response_query(q,qtype,DNS_C_IN)) return -1;
    if (dns_packet_typematch(qtype,DNS_T_ANY)) {
      if (!response_noany(q)) return -1;
    } else if (dns_packet_typematch(qtype,DNS_T_OPT)) {
      if (!response_noopt(q)) return -1;
    } else if (dns_packet_typematch(qtype,DNS_T_AXFR)||dns_packet_typematch(qtype,DNS_T_IXFR)) {
      if (!response_noaxfr(q)) return -1;
    } else if (IP4_LEN == dd4(q,localhost,ip4) && 127 == (unsigned char)ip4[3]) {
      if (dns_packet_typematch(qtype,DNS_T_A)) {
        if (!response_rstart(q,qtype,TTL_STATIC_POSITIVE)) return -1;
        byte_reverse(ip4, sizeof ip4); /* They are little-endian in the domain name. */
        if (!response_addbytes(ip4,sizeof ip4)) return -1;
        response_rfinish(RESPONSE_ANSWER);
      } else if (dns_packet_typematch(qtype,DNS_T_AAAA)) {
        char ip6[IP6_SANS_SCOPE_LEN];

        byte_zero(ip6, sizeof ip6);
        byte_reverse(ip4, sizeof ip4); /* They are little-endian in the domain name. */
        byte_copy(ip6 + sizeof ip6 - sizeof ip4,sizeof ip4,ip4);
        ip6[10] = ip6[11] = 0xFF;
        if (!response_rstart(q,qtype,TTL_STATIC_POSITIVE)) return -1;
        if (!response_addbytes(ip6,sizeof ip6)) return -1;
        response_rfinish(RESPONSE_ANSWER);
      }
    } else {
      if (dns_packet_typematch(qtype,DNS_T_A)) {
        if (!response_rstart(q,qtype,TTL_STATIC_POSITIVE)) return -1;
        if (!response_addbytes("\177\000\000\001",IP4_LEN)) return -1;
        response_rfinish(RESPONSE_ANSWER);
      } else if (dns_packet_typematch(qtype,DNS_T_AAAA)) {
        if (!response_rstart(q,qtype,TTL_STATIC_POSITIVE)) return -1;
        if (!response_addbytes("\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\001",IP6_SANS_SCOPE_LEN)) return -1;
        response_rfinish(RESPONSE_ANSWER);
      }
    }
    return dns_transmit_set(&dns_resolve_tx,response,response_len);
  }
  if (dns_domain_equal(q,ipv4onlyarpa)) {   /* RFC 8880 */
    if (!response_query(q,qtype,DNS_C_IN)) return -1;
    if (dns_packet_typematch(qtype,DNS_T_ANY)) {
      if (!response_noany(q)) return -1;
    } else if (dns_packet_typematch(qtype,DNS_T_OPT)) {
      if (!response_noopt(q)) return -1;
    } else if (dns_packet_typematch(qtype,DNS_T_AXFR)||dns_packet_typematch(qtype,DNS_T_IXFR)) {
      if (!response_noaxfr(q)) return -1;
    } else if (dns_packet_typematch(qtype,DNS_T_A)) {
        if (!response_rstart(q,qtype,TTL_STATIC_POSITIVE)) return -1;
        if (!response_addbytes("\300\000\000\252",IP4_LEN)) return -1;
        response_rfinish(RESPONSE_ANSWER);
        if (!response_rstart(q,qtype,TTL_STATIC_POSITIVE)) return -1;
        if (!response_addbytes("\300\000\000\253",IP4_LEN)) return -1;
        response_rfinish(RESPONSE_ANSWER);
    }
    return dns_transmit_set(&dns_resolve_tx,response,response_len);
  } else
  if (dns_domain_suffix(q,ipv4onlyarpa)) {  /* RFC 8880 */
    if (!response_query(q,qtype,DNS_C_IN)) return -1;
    response_nxdomain();
    return dns_transmit_set(&dns_resolve_tx,response,response_len);
  } else
  if (IP4_LEN == dd4(q,inaddrarpa,ip4)) {
    if (192 == (unsigned char)ip4[3]
    &&  0 == (unsigned char)ip4[2]
    &&  0 == (unsigned char)ip4[1]
    &&  (170 == (unsigned char)ip4[0] || 171 == (unsigned char)ip4[0])
    ) {  /* RFC 8880 */
      if (!response_query(q,qtype,DNS_C_IN)) return -1;
      if (dns_packet_typematch(qtype,DNS_T_ANY)) {
        if (!response_noany(q)) return -1;
      } else if (dns_packet_typematch(qtype,DNS_T_OPT)) {
        if (!response_noopt(q)) return -1;
      } else if (dns_packet_typematch(qtype,DNS_T_AXFR)||dns_packet_typematch(qtype,DNS_T_IXFR)) {
        if (!response_noaxfr(q)) return -1;
      } else if (dns_packet_typematch(qtype,DNS_T_PTR)) {
        if (!response_rstart(q,qtype,TTL_STATIC_POSITIVE)) return -1;
        if (!response_addname(ipv4onlyarpa)) return -1;
        response_rfinish(RESPONSE_ANSWER);
      }
      return dns_transmit_set(&dns_resolve_tx,response,response_len);
    } else
    if (127 == (unsigned char)ip4[3]) {     /* long-standing /etc/hosts mapping, should have been in RFC 6761 */
      if (!response_query(q,qtype,DNS_C_IN)) return -1;
      if (dns_packet_typematch(qtype,DNS_T_ANY)) {
        if (!response_noany(q)) return -1;
      } else if (dns_packet_typematch(qtype,DNS_T_OPT)) {
        if (!response_noopt(q)) return -1;
      } else if (dns_packet_typematch(qtype,DNS_T_AXFR)||dns_packet_typematch(qtype,DNS_T_IXFR)) {
        if (!response_noaxfr(q)) return -1;
      } else if (dns_packet_typematch(qtype,DNS_T_PTR)) {
        if (!response_rstart(q,qtype,TTL_STATIC_POSITIVE)) return -1;
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
      }
      return dns_transmit_set(&dns_resolve_tx,response,response_len);
    }
  } else
  if (dns_domain_equal(q,"\0011\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\003ip6\004arpa")) {
    if (!response_query(q,qtype,DNS_C_IN)) return -1;
    if (dns_packet_typematch(qtype,DNS_T_ANY)) {
      if (!response_noany(q)) return -1;
    } else if (dns_packet_typematch(qtype,DNS_T_OPT)) {
      if (!response_noopt(q)) return -1;
    } else if (dns_packet_typematch(qtype,DNS_T_AXFR)||dns_packet_typematch(qtype,DNS_T_IXFR)) {
      if (!response_noaxfr(q)) return -1;
    } else if (dns_packet_typematch(qtype,DNS_T_PTR)) {
      if (!response_rstart(q,qtype,TTL_STATIC_POSITIVE)) return -1;
      if (!response_addname(localhost)) return -1;
      response_rfinish(RESPONSE_ANSWER);
    }
    return dns_transmit_set(&dns_resolve_tx,response,response_len);
  } else
  {
    if (dns_packet_typematch(qtype,DNS_T_ANY)) {
      if (!response_query(q,qtype,DNS_C_IN)) return -1;
      if (!response_noany(q)) return -1;
      return dns_transmit_set(&dns_resolve_tx,response,response_len);
    } else if (dns_packet_typematch(qtype,DNS_T_OPT)) {
      if (!response_query(q,qtype,DNS_C_IN)) return -1;
      if (!response_noopt(q)) return -1;
      return dns_transmit_set(&dns_resolve_tx,response,response_len);
    } else if (dns_packet_typematch(qtype,DNS_T_AXFR)||dns_packet_typematch(qtype,DNS_T_IXFR)) {
      if (!response_query(q,qtype,DNS_C_IN)) return -1;
      if (!response_noaxfr(q)) return -1;
      return dns_transmit_set(&dns_resolve_tx,response,response_len);
    }
  }

  return 0;
}

int dns_resolve_servers(const char *q,const char qtype[2],const struct ip_address server_list[],unsigned int server_count,unsigned int port,int flagrecursive)
{
  int r;

  if ((r = handle_specials(q,qtype,server_count)) != 0) return r;
  return dns_resolve_servers_nospecials(q,qtype,server_list,server_count,port,flagrecursive);
}

int dns_resolve(const char *q,const char qtype[2])
{
  struct ip_address server_list[16];
  unsigned int server_count = sizeof server_list/sizeof *server_list;
  unsigned int port;
  int r;

  if (dns_resolvconfip(q,server_list,server_count,&server_count,&port) == -1) return -1;
  if ((r = handle_specials(q,qtype,server_count)) != 0) return r;
  return dns_resolve_servers(q,qtype,server_list,server_count,port,1);
}
