#ifndef DNS_PACKET_H
#define DNS_PACKET_H

/* DNS wire-format packet parsing utilities. */

extern unsigned int dns_packet_copy(const char *,unsigned int,unsigned int,char *,unsigned int);
extern unsigned int dns_packet_getname(const char *,unsigned int,unsigned int,char **);
extern unsigned int dns_packet_skipname(const char *,unsigned int,unsigned int);
extern int dns_packet_rrtypematch(const char [10],const char [2]);
extern int dns_packet_typematch(const char [2],const char [2]);
extern int dns_packet_rrinternetclass(const char [10]);
extern int dns_packet_internetclass(const char [2]);

#define HEADER_ID 0
#define HEADER_QUERY 4
#define HEADER_ANSWER 6
#define HEADER_AUTHORITY 8
#define HEADER_ADDITIONAL 10
#define HEADER_SIZE 12
#define RRFIXED_TYPE 0
#define RRFIXED_CLASS 2
#define RRFIXED_TTL 4
#define RRFIXED_DATALEN 8
#define RRFIXED_SIZE 10

#endif
