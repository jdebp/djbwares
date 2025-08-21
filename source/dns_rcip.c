#include "str.h"
#include "scan.h"
#include "taia.h"
#include "openreadclose.h"
#include "byte.h"
#include "ip.h"
#include "env.h"
#include "dns_resolve.h"
#include "dns_domain.h"

static stralloc data = stralloc_static_0;

/* The proxy servers fall into 5 distinct groups:
** 4. The local. superdomain and various subdomains of ip-addr.arpa. from RFC 8375.
** 3. The onion. superdomain from RFC 7686.
** 2. The service.arpa. superdomain from RFC 9665.
** 1. The home.arpa. superdomain from RFC 8375.
** 0. Everything else.
** Each group has its own server list, configuration environment variables, and directive in resolv.conf.
*/

#define NUM_GROUPS	5
#define MAX_SERVERS	16

static const char * ipvarname[NUM_GROUPS] = {
  "DNSCACHEIP",
  "DNSCACHEIP_HOME",
  "DNSCACHEIP_DNSSD",
  "DNSCACHEIP_ONION",
  "DNSCACHEIP_MDNS",
};
static const char * portvarname[NUM_GROUPS] = {
  "DNSCACHEPORT",
  "DNSCACHEPORT_HOME",
  "DNSCACHEPORT_DNSSD",
  "DNSCACHEPORT_ONION",
  "DNSCACHEPORT_MDNS",
};
static const char * directive[NUM_GROUPS] = {
  "nameserver",
  "home-nameserver",
  "dnssd-nameserver",
  "onion-nameserver",
  "mdns-nameserver",
};
static struct ip_address ip[NUM_GROUPS][MAX_SERVERS] =
{
  { IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT },
  { IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT },
  { IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT },
  { IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT },
  { IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT, IP_ADDRESS_INIT },
};
static unsigned int c[NUM_GROUPS] = { 0, 0, 0, 0, 0 };
static unsigned int p[NUM_GROUPS] = { 53, 53, 53, 53, 5353 };

static int isspacetab(const char cc) { return ' ' == cc || '\t' == cc; }

static int init()
{
  unsigned int j, g;
  unsigned int d[NUM_GROUPS] = { 0, 0, 0, 0, 0 };

  for (g = 0;g < NUM_GROUPS;++g) {
    char * x;

    c[g] = 0;
    for (j = 0;j < MAX_SERVERS; ++j)
      ip_make_unassigned(&ip[g][j]);
    p[g] = g != 4 ? 53 : 5353;

    x = env_get(portvarname[g]);
    if (!x && g != 0 && g != 4) x = env_get(portvarname[0]);
    if (x) {
      unsigned long port;
      j = scan_ulong(x,&port);
      if (j && !x[j]) p[g] = port;
    }

    x = env_get(ipvarname[g]);
    if (!x && g != 0 && g != 4) x = env_get(ipvarname[0]);
    if (x)
      while (c[g] < MAX_SERVERS) {
        if (*x == ' ' || *x == '\t' || *x == '\n')
          ++x;
        else {
          unsigned int i;

          i = ip_scan(x,ip[g] + c[g],':');
          if (!i) break;
          x += i;
          c[g]++;
        }
      }
  }

  j = 0;
  for (g = 0;g < NUM_GROUPS;++g) {
    d[g] = c[g];
    j += !d[g];
  }

  if (j) {
    int i;

    i = openreadclose("/etc/resolv.conf",&data,64);
    if (i == -1) return -1;
    if (i) {
      if (!stralloc_append(&data,"\n")) return -1;
      i = 0;
      for (j = 0;j < data.len;++j)
        if (data.s[j] == '\n') {
          unsigned int l;

          for (g = 0;g < NUM_GROUPS;++g) {
            if (d[g]) continue;
            l = str_len(directive[g]);
            if (i + l + 1 < j && byte_equal(directive[g],l,data.s + i) && isspacetab(data.s[i + l])) {
              i += l + 1;
              while (isspacetab(data.s[i]))
                ++i;
              if (c[g] < MAX_SERVERS)
                if (ip_scan_n(data.s + i,j - i,ip[g] + c[g],':')) {
                  if (ip_is_zero(ip[g] + c[g]))
                    ip_make_loopback(ip[g] + c[g]);
                  c[g]++;
                }
            }
            i = j + 1;
          }
        }

    }
  }

  for (g = 0;g < NUM_GROUPS;++g) {
    if (c[g]) continue;
    if (g != 4) {
      ip_make_loopback4(ip[g] + c[g]);
      c[g]++;
      ip_make_loopback6(ip[g] + c[g]);
      c[g]++;
    } else {
      ip_make4(ip[g] + c[g],"\340\000\000\373");
      c[g]++;
      ip_make6(ip[g] + c[g],"\377\002\000\000\000\000\000\000\000\000\000\000\000\000\000\373",0);
      c[g]++;
    }
  }
  return 0;
}

static int find_group(const char * q)
{
  if (dns_domain_suffix(q,"\005onion")) return 3;
  if (dns_domain_suffix(q,"\005local")
  ||  dns_domain_suffix(q,"\003254\003169\007in-addr\004arpa")
  ||  dns_domain_suffix(q,"\0018\001e\001f\003ip6\004arpa")
  ||  dns_domain_suffix(q,"\0019\001e\001f\003ip6\004arpa")
  ||  dns_domain_suffix(q,"\001a\001e\001f\003ip6\004arpa")
  ||  dns_domain_suffix(q,"\001b\001e\001f\003ip6\004arpa")
  ) return 4;
  if (dns_domain_suffix(q,"\007service\004arpa")) return 2;
  if (dns_domain_suffix(q,"\004home\004arpa")) return 1;
  return 0;
}

static int ok = 0;
static unsigned int uses;
static struct taia deadline;

int dns_resolvconfip(const char * q,struct ip_address s[],unsigned int m,unsigned int *count,unsigned int *port)
{
  struct taia now;
  unsigned int j, g;

  taia_now(&now);
  if (taia_less(&deadline,&now)) ok = 0;
  if (!uses) ok = 0;

  if (!ok) {
    if (init() == -1) return -1;
    taia_uint(&deadline,600);
    taia_add(&deadline,&now,&deadline);
    uses = 10000;
    ok = 1;
  }

  --uses;
  g = find_group(q);
  for (j = 0;j < c[g] && j < m;++j) s[j] = ip[g][j];
  while (j < m) ip_make_unassigned(s + j++);
  *count = c[g];
  *port = p[g];
  return 0;
}
