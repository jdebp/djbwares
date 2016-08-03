/* see env.c */

#include "env_write.h"
#include "str.h"

#if 0	// Superseded by env_get.c
extern char *env_get(s)
char *s;
{
 int i;
 int slen;
 char *envi;

 slen = str_len(s);
 for (i = 0;envi = environ[i];++i)
   if ((!str_diffn(s,envi,slen)) && (envi[slen] == '='))
     return envi + slen + 1;
 return 0;
}
#endif

extern char *env_pick()
{
 return environ[0];
}

extern char *env_findeq(char *s)
{
 for (;*s;++s)
   if (*s == '=')
     return s;
 return 0;
}
