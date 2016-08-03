#!/bin/sh -e
redo-ifchange trysgprm.c compile link
if ( ./compile trysgprm.o trysgprm.c trysgprm.d && ./link trysgprm trysgprm.o ) >/dev/null 2>&1 
then
	echo \#define HASSIGPROCMASK 1 > "$3"
else
	echo '/* sysdep: -sigprocmask */' > "$3"
fi
#rm -f trysgprm.o trysgprm
