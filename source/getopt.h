#ifndef GETOPT_H
#define GETOPT_H

#ifndef GETOPTNOSHORT
#ifndef SGETOPT_H
#define getopt getoptmine
#define optarg subgetoptarg
#define optind subgetoptind
#define optpos subgetoptpos
#define opterr getopterr
#define optproblem subgetoptproblem
#define optprogname getoptprogname
#define opteof subgetoptdone
#endif
#endif

#include "subgetopt.h"

extern int getoptmine();
extern int getopterr;
extern char *getoptprogname;

#endif
