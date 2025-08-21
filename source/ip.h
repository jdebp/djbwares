#ifndef IP_H
#define IP_H

#include "uint32.h"

#define IP4_LEN 4
#define IP6_LEN 20
#define IP6_SANS_SCOPE_LEN 16
#define IP6_SCOPE_ID_LEN 4
struct ip_address { 
  unsigned char len;
  union {
    unsigned char d4[IP4_LEN];
    unsigned char d6[IP6_LEN];
  };
} ;
#define IP_ADDRESS_INIT { 0, {} }

extern unsigned int ip_fmt(char * s,const struct ip_address * ip,char sep);
#define IP_FMT 50
extern unsigned int ip_scan_n(const char * s,unsigned int len,struct ip_address * ip,char sep);
extern unsigned int ip_scan(const char * s,struct ip_address * ip,char sep);
extern unsigned int ip_scanbracket(const char * s,struct ip_address * ip,char sep);
extern void ip_make_unassigned(struct ip_address * ip);
extern void ip_make_zero4(struct ip_address * ip);
extern void ip_make_zero6(struct ip_address * ip);
extern void ip_make4(struct ip_address * ip,const char [IP4_LEN]);
extern void ip_make6(struct ip_address * ip,const char [IP6_SANS_SCOPE_LEN],uint32);
extern void ip_make_loopback4(struct ip_address * ip);
extern void ip_make_loopback6(struct ip_address * ip);
extern int ip_make_loopback(struct ip_address * ip);
extern int ip_make_zero(struct ip_address * ip);
extern int ip_is4(const struct ip_address * ip);
extern int ip_is6(const struct ip_address * ip);
extern int ip_is_unassigned(const struct ip_address * ip);
extern int ip_is_zero(const struct ip_address * ip);
extern int ip_equals(const struct ip_address * ip1,const struct ip_address *ip2);

#endif
