#ifndef IP6_H
#define IP6_H

extern unsigned int ip6_scan(const char *,char [20],char sep);
extern unsigned int ip6_fmt(char *,const char [20],char sep);

#define IP6_FMT 50
#define IP6_LEN 20

#endif
