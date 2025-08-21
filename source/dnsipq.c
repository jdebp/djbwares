#include "buffer.h"
#include "exit.h"
#include "strerr.h"
#include "ip.h"
#include "dns_resolve.h"
#include "dns_random.h"

#define FATAL "dnsipq: fatal: "

static char seed[128];

static stralloc in;
static stralloc fqdn;
static stralloc out;
static char str[IP_FMT];

int main(int argc,char **argv)
{
  unsigned int i;

  dns_random_init(seed);

  (void)argc;
  if (*argv) ++argv;

  while (*argv) {
    if (!stralloc_copys(&in,*argv))
      strerr_die2x(111,FATAL,"out of memory");
    if (dns_ip_qualify(&out,&fqdn,&in) == -1)
      strerr_die4sys(111,FATAL,"unable to find IP address for ",*argv,": ");

    buffer_put(buffer_1,fqdn.s,fqdn.len);
    buffer_puts(buffer_1," ");
    for (i = 0;i + sizeof(struct ip_address) <= out.len;i += sizeof(struct ip_address)) {
      buffer_put(buffer_1,str,ip_fmt(str,out.s + i,':'));
      buffer_puts(buffer_1," ");
    }
    buffer_puts(buffer_1,"\n");

    ++argv;
  }

  buffer_flush(buffer_1);
  return 0;
}
