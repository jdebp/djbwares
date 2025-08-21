#include "byte.h"
#include "dns_sortip.h"
#include "dns_random.h"

/* XXX: sort servers by configurable notion of closeness? */
/* XXX: pay attention to competence of each server? */

void dns_sortip(struct ip_address *s,unsigned int n)
{
  unsigned int i;
  struct ip_address tmp;

  while (n > 1) {
    i = dns_random(n);
    --n;
    tmp = s[n];
    s[n] = s[i];
    s[i] = tmp;
  }
}
