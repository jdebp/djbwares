#ifndef RESPONSE_H
#define RESPONSE_H

#include "uint32.h"

#define MAX_RESPONSE 65535

extern char response[];
extern unsigned int response_len;

extern void response_id(const char id[2]);
extern int response_query(const char *qname,const char qtype[2],const char qclass[2]);
extern void response_nxdomain(void);
extern void response_refuse(void);
extern void response_servfail(void);
extern void response_tc(void);
extern int response_noany(const char *name);
extern int response_noopt(const char *name);
extern int response_noaxfr(const char *name);
extern int response_badip4(const char *name);

extern int response_addbytes(const char *,unsigned int);
extern int response_addname(const char *);
extern void response_hidettl(void);
extern int response_rstart(const char *,const char type[2],uint32);
extern void response_rfinish(int);

#define RESPONSE_ANSWER 6
#define RESPONSE_AUTHORITY 8
#define RESPONSE_ADDITIONAL 10

extern int response_cname(const char *,const char *,uint32 ttl);
extern int response_placeholder_soa(const char *apex,uint32 ttl);

#endif
