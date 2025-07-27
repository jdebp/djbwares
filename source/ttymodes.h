#ifndef TTYMODES_H
#define TTYMODES_H

#include <sys/ioctl.h>
#include <termios.h>

struct ttymodes {
  struct termios ti;
  struct winsize ws;
} ;

extern int ttymodes_gett(struct ttymodes *,int);
extern int ttymodes_getw(struct ttymodes *,int);
extern int ttymodes_get(struct ttymodes *,int);
extern int ttymodes_sett(const struct ttymodes *,int);
extern int ttymodes_setw(const struct ttymodes *,int);
extern int ttymodes_set(const struct ttymodes *,int);

extern void ttymodes_makeraw(struct ttymodes *);
extern void ttymodes_sane(struct ttymodes *);

#endif
