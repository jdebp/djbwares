#include "buffer.h"
#include "exit.h"
#include "strerr.h"
#include "ip4.h"
#include "ip6.h"
#include "dns.h"

#define FATAL "dnsname: fatal: "

static char seed[128];

static char ip4[4];
static char ip6[16];
static stralloc out;

int main(int argc,char **argv)
{
  int l;

  dns_random_init(seed);

  (void)argc;
  if (*argv) ++argv;

  while (*argv) {
    if ((l = ip4_scan(*argv,ip4)) && !(*argv)[l]) {
      if (dns_name4(&out,ip4) == -1)
	strerr_die4sys(111,FATAL,"unable to find host name for ",*argv,": ");

      buffer_put(buffer_1,out.s,out.len);
      buffer_puts(buffer_1,"\n");
    } else if ((l = ip6_scan(*argv,ip6,':')) && !(*argv)[l]) {
      if (dns_name6(&out,ip6) == -1)
	strerr_die4sys(111,FATAL,"unable to find host name for ",*argv,": ");

      buffer_put(buffer_1,out.s,out.len);
      buffer_puts(buffer_1,"\n");
    } else
      strerr_die3x(111,FATAL,"unable to parse IP address ",*argv);

    ++argv;
  }

  buffer_flush(buffer_1);
  _exit(0);
}
