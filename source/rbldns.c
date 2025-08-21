#include <unistd.h>
#include "str.h"
#include "byte.h"
#include "ip.h"
#include "open.h"
#include "env.h"
#include "cdb.h"
#include "dns_constants.h"
#include "dns_server.h"
#include "dns_domain.h"
#include "dd.h"
#include "strerr.h"
#include "response.h"

static char *base;

static struct cdb c;
static char key[5];
static char data[100 + IP_FMT];

static int doit(const char *q,const char qtype[2])
{
  int flaga;
  int flagtxt;
  char ch;
  char a[IP4_LEN];
  uint32 ipnum;
  struct ip_address ip;
  int r = 0;
  uint32 dlen;
  int i;

  if (byte_equal(qtype,2,DNS_T_ANY)) {
    if (!response_noany(q)) return 0;
    return 1;
  }
  if (byte_equal(qtype,2,DNS_T_OPT)) {
    if (!response_noopt(q)) return 0;
    return 1;
  }

  flaga = byte_equal(qtype,2,DNS_T_A);
  flagtxt = byte_equal(qtype,2,DNS_T_TXT);
  if (!flaga && !flagtxt) goto REFUSE;

  if (dd4(q,base,a) != IP4_LEN) goto REFUSE;
  uint32_unpack_big(a,&ipnum);
  ip_make4(&ip,a);

  for (i = 0;i <= 24;++i) {
    ipnum >>= i;
    ipnum <<= i;
    uint32_pack_big(key,ipnum);
    key[4] = 32 - i;
    r = cdb_find(&c,key,5);
    if (r == -1) return 0;
    if (r) break;
  }
  if (!r) { response_nxdomain(); return 1; }

  r = cdb_find(&c,"",0);
  if (r == -1) return 0;
  if (r && ((dlen = cdb_datalen(&c)) >= 4)) {
    if (dlen > 100) dlen = 100;
    if (cdb_read(&c,data,dlen,cdb_datapos(&c)) == -1) return 0;
  }
  else {
    dlen = 12;
    byte_copy(data,dlen,"\177\0\0\2Listed $");
  }

  if ((dlen >= 5) && (data[dlen - 1] == '$')) {
    --dlen;
    dlen += ip_fmt(data + dlen,&ip,':');
  }

  if (flaga) {
    if (!response_rstart(q,DNS_T_A,2048)) return 0;
    if (!response_addbytes(data,4)) return 0;
    response_rfinish(RESPONSE_ANSWER);
  }
  if (flagtxt) {
    if (!response_rstart(q,DNS_T_TXT,2048)) return 0;
    ch = dlen - 4;
    if (!response_addbytes(&ch,1)) return 0;
    if (!response_addbytes(data + 4,dlen - 4)) return 0;
    response_rfinish(RESPONSE_ANSWER);
  }

  return 1;

  REFUSE:
  response_refuse();
  return 1;
}

int respond(const char *q,const char qtype[2],unsigned int max,const struct ip_address *ipremote)
{
  int fd;
  int result;

  (void)ipremote; /* Silence a compiler warning. */
  fd = open_read("data.cdb");
  if (fd == -1) return 0;
  cdb_init(&c,fd);
  result = doit(q,qtype);
  cdb_free(&c);
  close(fd);
  return result;
}

const char *fatal = "rbldns: fatal: ";
const char *starting = "starting rbldns\n";

void initialize(void)
{
  char *x;

  x = env_get("BASE");
  if (!x)
    strerr_die2x(111,fatal,"$BASE not set");
  if (!dns_domain_fromdot(&base,x,str_len(x)))
    strerr_die2x(111,fatal,"unable to parse $BASE");
}
