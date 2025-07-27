#ifndef IP4_H
#define IP4_H

extern unsigned int ip4_scan(const char *,char [4]);
extern unsigned int ip4_fmt(char *,const char [4]);

#define IP4_FMT 20
#define IP4_LEN 4

#endif
