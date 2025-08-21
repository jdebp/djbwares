#include "buffer.h"
#include "exit.h"
#include "strerr.h"
#include "ip.h"
#include "dns_resolve.h"
#include "dns_random.h"

#define FATAL "dnsname: fatal: "

static char seed[128];

static stralloc out;

int main(int argc,char **argv)
{
  dns_random_init(seed);

  (void)argc;
  if (*argv) ++argv;

  while (*argv) {
    int l;
    struct ip_address ip = IP_ADDRESS_INIT;

    l = ip_scan(*argv,&ip,':');
    if (0 >= l || (*argv)[l]) 
      strerr_die3x(111,FATAL,"unable to parse IP address ",*argv);
    if (dns_name(&out,&ip) == -1)
       strerr_die4sys(111,FATAL,"unable to find host name for ",*argv,": ");

    buffer_put(buffer_1,out.s,out.len);
    buffer_puts(buffer_1,"\n");

    ++argv;
  }

  buffer_flush(buffer_1);
  _exit(0);
}
