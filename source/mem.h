/* Public domain. */

#ifndef MEM_H
#define MEM_H

extern void mem_copy(void *, unsigned int, const void *);
extern void mem_copyr(void *, unsigned int, const void *);
extern int mem_diff(const void *, unsigned int, const void *);
extern void mem_zero(void *, unsigned int);
extern void mem_reverse(void *, unsigned int);

#define mem_equal(s,n,t) (!mem_diff((s),(n),(t)))

#endif
