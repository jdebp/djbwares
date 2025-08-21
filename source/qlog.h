#ifndef QLOG_H
#define QLOG_H

#include "uint16.h"

struct ip_address;
extern void qlog(const struct ip_address *,uint16,const char id[2],uint16,const char *,const char qtype[2],const char *);

#endif
