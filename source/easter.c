/* Public domain. */

#include <stdio.h>
#include <stdlib.h>
#include "caldate.h"

static const char *dayname[7] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" } ;

static char out[101];

int main(int argc, char** argv)
{
  struct caldate cd;
  long day;
  int weekday;
  int yearday;

  (void)argc; /* Silence a compiler warning. */
  while (*++argv) {
    cd.year = atoi(*argv);
    if (cd.year > 0) {
      caldate_easter(&cd);
      day = caldate_mjd(&cd);
      caldate_frommjd(&cd,day,&weekday,&yearday);
      if (caldate_fmt((char *) 0,&cd) + 1 >= sizeof out) return(1);
      out[caldate_fmt(out,&cd)] = 0;
      printf("%s %s  yearday %d  mjd %ld\n",dayname[weekday],out,yearday,day);
    }
  }
  return(0);
}
