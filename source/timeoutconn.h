#ifndef TIMEOUTCONN_H
#define TIMEOUTCONN_H

#include "uint16.h"

struct ip_address;
extern int timeoutconn(int,const struct ip_address *,uint16,unsigned int);

#endif
