#ifndef LOG_H
#define LOG_H

#include "uint64.h"
#include "ip.h"

extern void log_startup(void);

extern void log_query(uint64 *,const struct ip_address *,unsigned int,const char *,const char *,const char *,unsigned int);
extern void log_querydrop(uint64 *);
extern void log_querydone(uint64 *,unsigned int);

extern void log_tcpopen(const struct ip_address *,unsigned int);
extern void log_tcpclose(const struct ip_address *,unsigned int);

extern void log_synthetic(const char *,const char *,unsigned int,unsigned int);

extern void log_cachedanswer(const char *,const char *,unsigned int);
extern void log_cachedcname(const char *,const char *,unsigned int);
extern void log_cachednxdomain(const char *,unsigned int);
extern void log_cachedns(const char *,const char *,unsigned int);
extern void log_cachedglue(const char *,const struct ip_address *,unsigned int);

extern void log_tx(const char *,const char *,const char *,const struct ip_address [16],unsigned int);
extern void log_root(const char *,const char *,const char *,unsigned int);
extern void log_want(const char *,const char *,unsigned int,unsigned int);

extern void log_nxdomain(const struct ip_address *,const char *,unsigned int);
extern void log_nodata(const struct ip_address *,const char *,const char *,unsigned int);
extern void log_servfail(const char *);
extern void log_no_servers(const char *);
extern void log_lame(const struct ip_address *,const char *,const char *);
extern void log_ignore_referral(const struct ip_address *,const char *,const char *,unsigned int);
extern void log_referral(const struct ip_address *,const char *,const char *,unsigned int);

extern void log_rr(const struct ip_address *,const char *,const char *,const char *,unsigned int,unsigned int);
extern void log_rrns(const struct ip_address *,const char *,const char *,unsigned int);
extern void log_rrcname(const struct ip_address *,const char *,const char *,unsigned int);
extern void log_rrptr(const struct ip_address *,const char *,const char *,unsigned int);
extern void log_rrmx(const struct ip_address *,const char *,const char *,const char *,unsigned int);
extern void log_rrsoa(const struct ip_address *,const char *,const char *,const char *,const char *,unsigned int);

extern void log_stats(void);

#endif
