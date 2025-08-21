#include <unistd.h>
#include "taia.h"
#include "env.h"
#include "byte.h"
#include "str.h"
#include "openreadclose.h"
#include "dns_resolve.h"

static stralloc data = {0,0,0};

static int init(stralloc *rules)
{
  char host[256];
  const char *x;
  int i;
  int k;

  if (!stralloc_copys(rules,"")) return -1;

  x = env_get("DNSREWRITEFILE");
  if (!x) x = "/etc/dnsrewrite";

  i = openreadclose(x,&data,64);
  if (i == -1) return -1;

  if (i) {
    unsigned int beg, end;
    if (!stralloc_append(&data,"\n")) return -1;
    beg = 0;
    for (end = 0;end < data.len;++end)
      if (data.s[end] == '\n') {
        if (!stralloc_catb(rules,data.s + beg,end - beg)) return -1;
        while (rules->len) {
          if (rules->s[rules->len - 1] != ' ')
          if (rules->s[rules->len - 1] != '\t')
          if (rules->s[rules->len - 1] != '\r')
            break;
          --rules->len;
        }
        if (!stralloc_0(rules)) return -1;
        beg = end + 1;
      }
    return 0;
  }

  x = env_get("LOCALDOMAIN");
  if (x) {
    unsigned int beg, end;
    if (!stralloc_copys(&data,x)) return -1;
    if (!stralloc_append(&data," ")) return -1;
    if (!stralloc_copys(rules,"?:")) return -1;
    beg = 0;
    for (end = 0;end < data.len;++end)
      if (data.s[end] == ' ') {
        if (!stralloc_cats(rules,"+.")) return -1;
        if (!stralloc_catb(rules,data.s + beg,end - beg)) return -1;
        beg = end + 1;
      }
    if (!stralloc_0(rules)) return -1;
    if (!stralloc_cats(rules,"*.:")) return -1;
    if (!stralloc_0(rules)) return -1;
    return 0;
  }

  i = openreadclose("/etc/resolv.conf",&data,64);
  if (i == -1) return -1;

  if (i) {
    unsigned int beg, end;
    if (!stralloc_append(&data,"\n")) return -1;
    beg = 0;
    for (end = 0;end < data.len;++end)
      if (data.s[end] == '\n') {
        if (byte_equal("search ",7,data.s + beg) || byte_equal("search\t",7,data.s + beg) || byte_equal("domain ",7,data.s + beg) || byte_equal("domain\t",7,data.s + beg)) {
          if (!stralloc_copys(rules,"?:")) return -1;
          beg += 7;
          while (beg < end) {
            k = byte_chr(data.s + beg,end - beg,' ');
            k = byte_chr(data.s + beg,k,'\t');
            if (!k) { ++beg; continue; }
            if (!stralloc_cats(rules,"+.")) return -1;
            if (!stralloc_catb(rules,data.s + beg,k)) return -1;
            beg += k;
          }
          if (!stralloc_0(rules)) return -1;
          if (!stralloc_cats(rules,"*.:")) return -1;
          if (!stralloc_0(rules)) return -1;
          return 0;
        }
        beg = end + 1;
      }
  }

  host[0] = 0;
  if (gethostname(host,sizeof host) == -1) return -1;
  host[(sizeof host) - 1] = 0;
  i = str_chr(host,'.');
  if (host[i]) {
    if (!stralloc_copys(rules,"?:")) return -1;
    if (!stralloc_cats(rules,host + i)) return -1;
    if (!stralloc_0(rules)) return -1;
  }
  if (!stralloc_cats(rules,"*.:")) return -1;
  if (!stralloc_0(rules)) return -1;

  return 0;
}

static int ok = 0;
static unsigned int uses;
static struct taia deadline;
static stralloc rules = {0,0,0}; /* defined if ok */

int dns_resolvconfrewrite(stralloc *out)
{
  struct taia now;

  taia_now(&now);
  if (taia_less(&deadline,&now)) ok = 0;
  if (!uses) ok = 0;

  if (!ok) {
    if (init(&rules) == -1) return -1;
    taia_uint(&deadline,600);
    taia_add(&deadline,&now,&deadline);
    uses = 10000;
    ok = 1;
  }

  --uses;
  if (!stralloc_copy(out,&rules)) return -1;
  return 0;
}
