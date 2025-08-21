#ifndef DNS_RANDOM_H
#define DNS_RANDOM_H

/* Common PRNG used to select UDP sources ports and message IDs. */

extern void dns_random_init(const char *);
extern unsigned int dns_random(unsigned int);

#endif
