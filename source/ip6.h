#ifndef IP6_H
#define IP6_H

extern unsigned int ip6_scan(const char *,char [IP6_LEN],char sep);
extern unsigned int ip6_fmt(char *,const char [IP6_LEN],char sep);

#define IP6_FMT 50

#endif
