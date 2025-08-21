#ifndef DNS_TRANSMIT_H
#define DNS_TRANSMIT_H

#include "ip.h"
#include "iopause.h"
#include "taia.h"
#include "dns_constants.h"

/* The low-level DNS client is built around multiple dns_transmit structures.
** The low-level methods are OO-like and operate on the given dns_transmit.
*/

struct dns_transmit {
  char *query; /* 0, or dynamically allocated */
  unsigned int querylen;
  char *packet; /* 0, or dynamically allocated */
  unsigned int packetlen;
  int s1; /* 0, or 1 + an open file descriptor */
  int tcpstate;
  unsigned int udploop;
  struct taia deadline;
  unsigned int pos;
  const struct ip_address *server_addresses; /* not owned */
  unsigned int server_count, current_server, port;
  struct ip_address localip;
  char qtype[2];
} ;

extern int dns_transmit_start(struct dns_transmit *,const struct ip_address [],unsigned int,unsigned int,int,const char *,const char *,const struct ip_address *);
extern void dns_transmit_free(struct dns_transmit *);
extern void dns_transmit_io(struct dns_transmit *,iopause_fd *,struct taia *);
extern int dns_transmit_get(struct dns_transmit *,const iopause_fd *,const struct taia *);
extern int dns_transmit_set(struct dns_transmit *,const char buf[],unsigned int len);
extern int dns_transmit_socket(struct dns_transmit *);

#endif
