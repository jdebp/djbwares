#ifndef DNS_SERVER_H
#define DNS_SERVER_H

/* Common content DNS server architecture. */

struct ip_address;

extern const char *fatal;
extern const char *starting;
extern void initialize(void);
extern int respond(const char *q,const char qtype[2],unsigned int max,const struct ip_address * ipremote);

#endif
