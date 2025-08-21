#ifndef IP4_H
#define IP4_H

extern unsigned int ip4_scan_n(const char *,unsigned int,char [IP4_LEN]);
extern unsigned int ip4_scan(const char *,char [IP4_LEN]);
extern unsigned int ip4_fmt(char *,const char [IP4_LEN]);

#define IP4_FMT 20

#endif
