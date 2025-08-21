#include "exit.h"
#include "byte.h"
#include "strerr.h"
#include "stralloc.h"
#include "buffer.h"
#include "dns_resolve.h"

#define FATAL "dnsqual: fatal: "

void nomem(void)
{
  strerr_die2x(111,FATAL,"out of memory");
}
void oops(void)
{
  strerr_die2sys(111,FATAL,"unable to parse: ");
}
void usage(void)
{
  strerr_die1x(100,"dnsqual: usage: dnsqual name");
}

static stralloc fqdn;
static stralloc iname;
static stralloc out;
static stralloc rules;

int
main(int argc,char **argv)
{
  const char * name = 0;
  unsigned int plus,fqdnlen;

  (void)argc;
  if (*argv) ++argv;

  name = *argv++;
  if (!name) usage();
  if (*argv) usage();

  if (dns_resolvconfrewrite(&rules) == -1) oops();
  if (!stralloc_copys(&iname,name)) nomem();
  if (dns_qualify_rules(&fqdn,&iname,&rules) == -1) oops();

  if (!stralloc_copys(&out,"")) oops();
  fqdnlen = fqdn.len;
  plus = byte_chr(fqdn.s,fqdnlen,'+');
  if (plus >= fqdnlen) {
    if (!stralloc_catb(&out,fqdn.s,fqdn.len)) oops();
    if (!stralloc_cats(&out,"\n")) oops();
  } else {
    unsigned int i;

    i = plus + 1;
    for (;;) {
      unsigned int j;

      j = byte_chr(fqdn.s + i,fqdnlen - i,'+');
      byte_copy(fqdn.s + plus,j,fqdn.s + i);
      fqdn.len = plus + j;
      if (!stralloc_catb(&out,fqdn.s,fqdn.len)) oops();
      if (!stralloc_cats(&out,"\n")) oops();
      i += j;
      if (i >= fqdnlen) break;
      ++i;
    }
  }

  buffer_putflush(buffer_1,out.s,out.len);
  return 0;
}
