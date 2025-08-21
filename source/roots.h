#ifndef ROOTS_H
#define ROOTS_H

struct ip_address;

extern int roots(struct ip_address *,unsigned int,unsigned int *,const char *);
extern int roots_same(const char *,const char *);
extern int roots_init(void);

#endif
