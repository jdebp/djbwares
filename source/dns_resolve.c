#include "iopause.h"
#include "taia.h"
#include "byte.h"
#include "dns.h"

struct dns_transmit dns_resolve_tx = {0,0,0};

int dns_resolve_servers(const char *q,const char qtype[2],const char servers[64],int flagrecursive)
{
  struct taia stamp;
  struct taia deadline;
  iopause_fd x[1];
  int r;

  if (dns_transmit_start(&dns_resolve_tx,servers,flagrecursive,q,qtype,"\0\0\0\0") == -1) return -1;

  for (;;) {
    taia_now(&stamp);
    taia_uint(&deadline,120);
    taia_add(&deadline,&deadline,&stamp);
    dns_transmit_io(&dns_resolve_tx,x,&deadline);
    iopause(x,1,&deadline,&stamp);
    r = dns_transmit_get(&dns_resolve_tx,x,&stamp);
    if (r == -1) return -1;
    if (r == 1) return 0;
  }
}

int dns_resolve(const char *q,const char qtype[2])
{
  char servers[64];

  if (dns_resolvconfip(servers) == -1) return -1;
  return dns_resolve_servers(q,qtype,servers,1);
}
