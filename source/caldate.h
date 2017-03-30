/* Public domain. */

#ifndef CALDATE_H
#define CALDATE_H

struct caldate {
  long year;
  int month;
  int day;
} ;

extern unsigned int caldate_fmt(char *s, const struct caldate *cd);
extern unsigned int caldate_scan(const char *s, struct caldate *cd);

extern void caldate_frommjd(struct caldate *cd, long day, int *pwday, int *pyday);
extern long caldate_mjd(const struct caldate *cd);
extern void caldate_normalize(struct caldate *cd);

extern void caldate_easter(struct caldate *cd);

#endif
