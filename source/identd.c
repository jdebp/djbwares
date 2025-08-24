#include "stralloc.h"
#include "sig.h"
#include "publicfile_server.h"
#include "ucspi.h"
#include "subfd.h"

static void log(const struct stralloc *query)
{
  unsigned int i;
  const char *x;

  x = ucspi_get_remoteip_str("0", "0", "0");
  substdio_puts(subfderr,x);
  substdio_puts(subfderr," query ");

  for (i = 0;i < query->len && i < 100;++i) {
    char ch = query->s[i];
    if (ch < 32) ch = '?';
    if (ch > 126) ch = '?';
    if (ch == ' ') ch = '_';
    substdio_put(subfderr,&ch,1);
  }
  if (i == 100)
    substdio_puts(subfderr,"...");

  substdio_puts(subfderr,"\n");
  substdio_flush(subfderr);
}

void doit(void)
{
  sig_ignore(sig_pipe);

  for (;;) {
    if (!readline()) break;

    if (!line.len) break;

    log(&line);
    out_put(line.s,line.len);
    out_puts(":USERID:Xenix:root\r\n");
    out_flush();
  }
}
