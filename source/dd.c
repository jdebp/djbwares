#include "dns_domain.h"
#include "dd.h"
#include "ip.h"
#include "ip4.h"
#include "ip6.h"

int dd4(const char *q,const char *base,char ip[IP4_LEN])
{
  int j;
  unsigned int x;

  for (j = 0;;++j) {
    if (dns_domain_equal(q,base)) return j;
    if (j >= IP4_LEN) return -1;

    if (*q <= 0) return -1;
    if (*q >= 4) return -1;
    if ((q[1] < '0') || (q[1] > '9')) return -1;
    x = q[1] - '0';
    if (*q == 1) {
      ip[j] = x;
      q += 2;
      continue;
    }
    if (!x) return -1;
    if ((q[2] < '0') || (q[2] > '9')) return -1;
    x = x * 10 + (q[2] - '0');
    if (*q == 2) {
      ip[j] = x;
      q += 3;
      continue;
    }
    if (!x) return -1;
    if ((q[3] < '0') || (q[3] > '9')) return -1;
    x = x * 10 + (q[3] - '0');
    if (x > 255) return -1;
    ip[j] = x;
    q += 4;
  }
}

static char hex[16] = "0123456789abcdef";

int dd6(const char *q,const char *base,char ip[IP6_SANS_SCOPE_LEN])
{
  int j,k;
  unsigned int x;

  for (j = 0;;++j) {
    if (dns_domain_equal(q,base)) return j;
    if (j >= IP6_SANS_SCOPE_LEN * 2) return -1;

    if (*q != 1) return -1;
    for (k = 16;k--;) {
      if (q[1] == hex[k]) break;
    }
    if (k < 0) return -1;
    x = k;
    if (j & 1) {
      ip[j/2] = (ip[j/2] & 0x0f) | (x << 4);
    } else {
      ip[j/2] = x;
    }
    q += 2;
  }
}
