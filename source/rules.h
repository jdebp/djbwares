#ifndef RULES_H
#define RULES_H

#include "stralloc.h"

extern stralloc rules_name;
extern int rules(void (*)(char *,unsigned int),int,const char *,const char *,const char *);

#endif
