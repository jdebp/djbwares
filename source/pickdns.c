#include <unistd.h>
#include "byte.h"
#include "case.h"
#include "dns_constants.h"
#include "dns_server.h"
#include "dns_random.h"
#include "dns_domain.h"
#include "dns_sortip.h"
#include "ip.h"
#include "ip4.h"
#include "open.h"
#include "cdb.h"
#include "response.h"

const char *fatal = "pickdns: fatal: ";
const char *starting = "starting pickdns\n";

static char seed[128];

void initialize(void)
{
  dns_random_init(seed);
}

static struct cdb c;
static char key[258];
static char data[512];

static int doit(const char *q,const char qtype[2],const struct ip_address *ip)
{
  int r = -1;
  uint32 dlen;
  unsigned int qlen;
  int flaga;
  int flagaaaa;
  int flagmx;

  qlen = dns_domain_length(q);
  if (qlen > 255) return 0; /* impossible */

  if (byte_equal(qtype,2,DNS_T_ANY)) {
    if (!response_noany(q)) return 0;
    return 1;
  } else
  if (byte_equal(qtype,2,DNS_T_OPT)) {
    if (!response_noopt(q)) return 0;
    return 1;
  }

  flaga = byte_equal(qtype,2,DNS_T_A);
  flagaaaa = byte_equal(qtype,2,DNS_T_AAAA);
  flagmx = byte_equal(qtype,2,DNS_T_MX);
  if (!flaga && !flagaaaa && !flagmx) goto REFUSE;

  if (ip_is4(ip)) {
    key[0] = '%';
    byte_copy(key + 1,4,ip->d4);

    r = cdb_find(&c,key,5);
    if (!r) r = cdb_find(&c,key,4);
    if (!r) r = cdb_find(&c,key,3);
    if (!r) r = cdb_find(&c,key,2);
  }
  if (r == -1) return 0;

  key[0] = '+';
  byte_zero(key + 1,2);
  if (r && (cdb_datalen(&c) == 2))
    if (cdb_read(&c,key + 1,2,cdb_datapos(&c)) == -1) return 0;

  byte_copy(key + 3,qlen,q);
  case_lowerb(key + 3,qlen + 3);

  r = cdb_find(&c,key,qlen + 3);
  if (!r) {
    byte_zero(key + 1,2);
    r = cdb_find(&c,key,qlen + 3);
  }
  if (!r) goto REFUSE;
  if (r == -1) return 0;
  dlen = cdb_datalen(&c);

  if (dlen > 512) dlen = 512;
  if (cdb_read(&c,data,dlen,cdb_datapos(&c)) == -1) return 0;

  if (flaga) {
    dns_sortip(data,dlen / sizeof(struct ip_address));
    if (dlen > sizeof(struct ip_address) * 3) dlen = sizeof(struct ip_address) * 3;
    while (dlen >= sizeof(struct ip_address)) {
      dlen -= sizeof(struct ip_address);
      if (!ip_is4(data + dlen)) continue;
      if (!response_rstart(q,DNS_T_A,5)) return 0;
      if (!response_addbytes(((const struct ip_address *)data + dlen)->d4,4)) return 0;
      response_rfinish(RESPONSE_ANSWER);
    }
  }
  if (flagaaaa) {
    dns_sortip(data,dlen / sizeof(struct ip_address));
    if (dlen > sizeof(struct ip_address) * 3) dlen = sizeof(struct ip_address) * 3;
    while (dlen >= sizeof(struct ip_address)) {
      dlen -= sizeof(struct ip_address);
      if (!ip_is6(data + dlen)) continue;
      if (!response_rstart(q,DNS_T_AAAA,5)) return 0;
      if (!response_addbytes(((const struct ip_address *)data + dlen)->d6,IP6_SANS_SCOPE_LEN)) return 0;
      response_rfinish(RESPONSE_ANSWER);
    }
  }

  return 1;

  REFUSE:
  response_refuse();
  return 1;
}

int respond(const char *q,const char qtype[2],const struct ip_address *ip)
{
  int fd;
  int result;

  fd = open_read("data.cdb");
  if (fd == -1) return 0;
  cdb_init(&c,fd);
  result = doit(q,qtype,ip);
  cdb_free(&c);
  close(fd);
  return result;
}
