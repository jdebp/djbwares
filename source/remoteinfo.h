#ifndef REMOTEINFO_H
#define REMOTEINFO_H

#include "stralloc.h"
#include "uint16.h"

struct ip_address;
extern int remoteinfo(stralloc *,const struct ip_address *,uint16,const struct ip_address *,uint16,unsigned int);

#endif
