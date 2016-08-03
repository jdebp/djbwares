#!/bin/sh -e
redo-ifchange chkshsgr warn-shsgr
if ./chkshsgr ; then : ; else cat warn-shsgr ; exit 1 ; fi
redo-ifchange tryshsgr.c compile link
if ( ./compile tryshsgr.o tryshsgr.c tryshsgr.d && ./link tryshsgr tryshsgr.o && ./tryshsgr ) >/dev/null 2>&1
then
	echo \#define HASSHORTSETGROUPS 1 > "$3"
else
	echo '/* sysdep: -shortsetgroups */' > "$3"
fi
