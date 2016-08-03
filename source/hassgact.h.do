#!/bin/sh -e
redo-ifchange trysgact.c compile link
if ( ./compile trysgact.o trysgact.c trysgact.d && ./link trysgact trysgact.o ) >/dev/null 2>&1 
then
	echo \#define HASSIGACTION 1 > "$3"
else
	echo '/* sysdep: -sigaction */' > "$3"
fi
#rm -f trysgact.o trysgact
