#include <sys/types.h>
#include <sys/stat.h>
#include "str.h"
#include "ip.h"
#include "okclient.h"

static char fn[3 + IP_FMT];

int okclient(const struct ip_address *ip)
{
  struct stat st;
  int i;

  fn[0] = 'i';
  fn[1] = 'p';
  fn[2] = '/';
  fn[3 + ip_fmt(fn + 3,ip,':')] = 0;

  for (;;) {
    if (stat(fn,&st) == 0) return 1;
    /* treat temporary error as rejection */
    i = str_rchr(fn,ip_is4(ip) ? '.' : ':');
    if (!fn[i]) return 0;
    fn[i] = 0;
  }
}
