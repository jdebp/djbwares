#ifndef LEAPSECS_H
#define LEAPSECS_H

struct tai;

extern int leapsecs_init(void);
extern int leapsecs_read(void);

extern void leapsecs_add(struct tai *t, int hit);
extern int leapsecs_sub(struct tai *t);

#endif
