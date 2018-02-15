#ifndef QUERY_H
#define QUERY_H

#include "dns.h"
#include "uint32.h"

#define QUERY_MAXLEVEL 5
#define QUERY_MAXALIAS 16
#define QUERY_MAXNS 16
#define QUERY_MAXNS_A (QUERY_MAXNS * 4)
#define QUERY_MAXNS_AAAA (QUERY_MAXNS * 16)

struct query {
  unsigned int loop;
  unsigned int level;
  char *name[QUERY_MAXLEVEL];
  char *control[QUERY_MAXLEVEL]; /* pointing inside name */
  char *ns[QUERY_MAXLEVEL][QUERY_MAXNS];
  char servers_a[QUERY_MAXLEVEL][QUERY_MAXNS_A];
  char servers_aaaa[QUERY_MAXLEVEL][QUERY_MAXNS_AAAA];
  char *alias[QUERY_MAXALIAS];
  uint32 aliasttl[QUERY_MAXALIAS];
  char localip[4];
  char type[2];
  char class[2];
  struct dns_transmit dt;
} ;

extern int query_start(struct query *,char *,char *,char *,char *);
extern void query_io(struct query *,iopause_fd *,struct taia *);
extern int query_get(struct query *,iopause_fd *,struct taia *);

extern void query_forwardonly(void);
extern void query_forwardfirst(void);

#endif
