#ifndef QUERY_H
#define QUERY_H

#include "dns_transmit.h"
#include "uint32.h"
#include "ip.h"

#define QUERY_MAXLEVEL 5
#define QUERY_MIN_USE_ROOTS_LEVEL 3
#define QUERY_MAXALIAS 16
#define QUERY_MAXNS 16
#define QUERY_MAXNS_ADDR 32 /* allowing one IPv4 and IPv6 address for each */

struct query {
  unsigned int loop;
  unsigned int level;
  char *name[QUERY_MAXLEVEL];
  char *control[QUERY_MAXLEVEL]; /* pointing inside name */
  char *ns[QUERY_MAXLEVEL][QUERY_MAXNS];
  struct ip_address server_addresses[QUERY_MAXLEVEL][QUERY_MAXNS_ADDR];
  unsigned int server_count[QUERY_MAXLEVEL];
  char *alias[QUERY_MAXALIAS];
  uint32 aliasttl[QUERY_MAXALIAS];
  struct ip_address localip;
  char type[2];
  char class[2];
  struct dns_transmit dt;
} ;

extern int query_start(struct query *,char *,char *,char *,const struct ip_address *);
extern void query_io(struct query *,iopause_fd *,struct taia *);
extern int query_get(struct query *,iopause_fd *,struct taia *);

extern void query_forwardonly(void);
extern void query_forwardfirst(void);

#endif
