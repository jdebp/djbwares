#ifndef DNS_ND_H
#define DNS_ND_H

/* Conversion of IP addresses into reverse-lookup domain names. */

#include "ip.h"

#define DNS_NAME4_LDOMAIN (17+11)
extern void dns_name4_ldomain(char name[DNS_NAME4_LDOMAIN],const char ip[IP4_LEN]);
#define DNS_NAME4_DOMAIN (17+14)
extern void dns_name4_domain(char name[DNS_NAME4_DOMAIN],const char ip[IP4_LEN]);
#define DNS_NAME6_DOMAIN (65+10)
extern void dns_name6_domain(char name[DNS_NAME6_DOMAIN],const char ip[IP6_LEN]);
#define DNS_NAME_DOMAIN 75
extern int dns_name_domain(char [DNS_NAME_DOMAIN],const struct ip_address *);

#endif
