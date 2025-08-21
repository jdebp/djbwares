#ifndef DD_H
#define DD_H

#include "ip.h"

extern int dd4(const char *q,const char *base,char [IP4_LEN]);
extern int dd6(const char *q,const char *base,char [IP6_SANS_SCOPE_LEN]);

#endif
