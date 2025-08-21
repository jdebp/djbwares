#ifndef DNS_RESOLVE_H
#define DNS_RESOLVE_H

#include "stralloc.h"
#include "ip.h"
#include "dns_constants.h"

/* The high-level DNS client is built around a single dns_transmit structure and various high-level methods.
** The high-level methods take a FQDN and return a set of results concatenanted into a generic stralloc.
** Mid-level methods take a FQDN and a query type and leave the answer in the dns_transmit structure.
*/

struct dns_transmit;

extern int dns_resolvconfip(const char *q,struct ip_address servers[],unsigned int,unsigned int *,unsigned int *);
extern int dns_resolve(const char *,const char *);
extern int dns_resolve_nospecials(const char *,const char *);
extern int dns_resolve_servers(const char *,const char *,const struct ip_address [],unsigned int,unsigned int,int);
extern int dns_resolve_servers_nospecials(const char *,const char *,const struct ip_address [],unsigned int,unsigned int,int);
extern struct dns_transmit dns_resolve_tx;

extern int dns_ip4(stralloc *,const stralloc *);
extern int dns_ip(stralloc *,const stralloc *);
extern int dns_name(stralloc *,const struct ip_address *);
extern int dns_name_multi(stralloc *,const struct ip_address *);
extern int dns_txt(stralloc *,const stralloc *);
extern int dns_mx(stralloc *,const stralloc *);
extern int dns_ns(stralloc *,const stralloc *);

extern int dns_resolvconfrewrite(stralloc *);
extern int dns_qualify_rules(stralloc *,const stralloc *,const stralloc *);
extern int dns_ip_qualify(stralloc *,stralloc *,const stralloc *);

/* common to dnsname and dnsfilter */
extern int dns_name_packet(stralloc *out,const char *buf,unsigned int len);

#endif
