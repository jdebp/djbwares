#include <unistd.h>
#include "open.h"
#include "error.h"
#include "str.h"
#include "byte.h"
#include "error.h"
#include "direntry.h"
#include "ip.h"
#include "openreadclose.h"
#include "roots.h"
#include "uint16.h"
#include "dns_domain.h"

static stralloc data;

#define MAX_ROOTS 32

static int roots_find(const char *q,uint16 *count)
{
  unsigned int i;

  i = 0;
  while (i < data.len) {
    int j;

    j = dns_domain_length(data.s + i);
    uint16_unpack(data.s + i + j,count);
    if (dns_domain_equal(data.s + i,q)) return i + j + 2;
    i += j + 2;
    i += sizeof(struct ip_address) * *count;
  }
  return -1;
}

static int roots_search(const char *q,uint16 *count)
{
  int r;

  for (;;) {
    r = roots_find(q,count);
    if (r >= 0) return r;
    if (!*q) return -1; /* user misconfiguration */
    q += *q;
    q += 1;
  }
}

int roots(struct ip_address server_list[],unsigned int max,unsigned int *count,const char *q)
{
  int r;
  const struct ip_address * s;
  unsigned int j;
  uint16 count16;

  r = roots_find(q,&count16);
  if (r == -1) return 0;
  s = (const struct ip_address *)(data.s + r);
  for (j = 0;j < max;++j) {
    if (j < count16)
      server_list[j] = s[j];
    else
      ip_make_unassigned(server_list + j);
  }
  *count = count16;
  return 1;
}

int roots_same(const char *q,const char *q2)
{
  uint16 count;
  return roots_search(q,&count) == roots_search(q2,&count);
}

static int init2(DIR *dir)
{
  for (;;) {
    direntry *d;

    errno = 0;
    d = readdir(dir);
    if (!d) {
      if (errno) return 0;
      return 1;
    }

    if (d->d_name[0] != '.') {
      uint16 serverslen;
      static stralloc text; // Holds a persistent pointer to heap storage.
      struct ip_address servers[MAX_ROOTS];
      const char *fqdn;
      unsigned int i;
      unsigned int j;
      static char *q = 0;  // Holds a persistent pointer to heap storage.

      if (openreadclose(d->d_name,&text,32) != 1) return 0;
      if (!stralloc_append(&text,"\n")) return 0;

      fqdn = d->d_name;
      if (str_equal(fqdn,"@")) fqdn = ".";
      if (!dns_domain_fromdot(&q,fqdn,str_len(fqdn))) return 0;

      for (j = 0;j < MAX_ROOTS;++j)
	ip_make_unassigned(servers + j);

      serverslen = 0;
      j = 0;
      for (i = 0;i < text.len;++i)
	if (text.s[i] == '\n') {
	  if (serverslen < MAX_ROOTS)
	    if (ip_scan(text.s + j,servers + serverslen,':'))
	      serverslen += 1;
	  j = i + 1;
	}

      if (!stralloc_catb(&data,q,dns_domain_length(q))) return 0;
      if (!stralloc_catb(&data,&serverslen,sizeof serverslen)) return 0;
      if (!stralloc_catb(&data,servers,sizeof(struct ip_address) * serverslen)) return 0;
    }
  }
}

static int init1(void)
{
  DIR *dir;
  int r;

  if (chdir("servers") == -1) return 0;
  dir = opendir(".");
  if (!dir) return 0;
  r = init2(dir);
  closedir(dir);
  return r;
}

int roots_init(void)
{
  int fddir;
  int r;

  if (!stralloc_copys(&data,"")) return 0;

  fddir = open_read(".");
  if (fddir == -1) return 0;
  r = init1();
  if (fchdir(fddir) == -1) r = 0;
  close(fddir);
  return r;
}
