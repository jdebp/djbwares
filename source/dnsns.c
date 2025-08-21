#include "buffer.h"
#include "exit.h"
#include "strerr.h"
#include "uint16.h"
#include "byte.h"
#include "str.h"
#include "fmt.h"
#include "dns_random.h"
#include "dns_resolve.h"

#define FATAL "dnsns: fatal: "

void nomem(void)
{
  strerr_die2x(111,FATAL,"out of memory");
}

static char seed[128];

static stralloc fqdn;
static stralloc out;

int main(int argc,char **argv)
{
  dns_random_init(seed);

  (void)argc;
  if (*argv) ++argv;

  while (*argv) {
    unsigned int i;

    if (!stralloc_copys(&fqdn,*argv)) nomem();
    if (dns_ns(&out,&fqdn) == -1)
      strerr_die4sys(111,FATAL,"unable to find NS records for ",*argv,": ");

    i = 0;
    while (i < out.len) {
      int j;

      j = byte_chr(out.s + i,out.len - i,0);
      buffer_put(buffer_1,out.s + i,j);
      buffer_puts(buffer_1,"\n");
      i += j + 1;
    }

    ++argv;
  }

  buffer_flush(buffer_1);
  return 0;
}
