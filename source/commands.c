#include "buffer.h"
#include "stralloc.h"
#include "str.h"
#include "case.h"
#include "commands.h"

static stralloc cmd = stralloc_static_0;

int commands(buffer *ss,struct commands *c)
{
  int i;
  char *arg;
  char ch;

  for (;;) {
    if (!stralloc_copys(&cmd,"")) return -1;

    for (;;) {
      i = buffer_get(ss,&ch,1);
      if (i != 1) return i;
      if (ch == '\n') break;
      if (!ch) ch = '\n';
      if (!stralloc_append(&cmd,&ch)) return -1;
    }

    if (cmd.len > 0) if (cmd.s[cmd.len - 1] == '\r') --cmd.len;

    if (!stralloc_0(&cmd)) return -1;

    i = str_chr(cmd.s,' ');
    arg = cmd.s + i;
    while (*arg == ' ') ++arg;
    cmd.s[i] = 0;

    for (i = 0;c[i].verb;++i) if (case_equals(c[i].verb,cmd.s)) break;
    c[i].action(arg);
    if (c[i].flush) c[i].flush();
  }
}
