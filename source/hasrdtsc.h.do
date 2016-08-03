#!/bin/sh -e
redo-ifchange tryrdtsc.c compile link
if ( ./compile tryrdtsc.o tryrdtsc.c tryrdtsc.d && ./link tryrdtsc tryrdtsc.o ) >/dev/null 2>&1
then
	echo \#define HASRDTSC 1 > "$3"
else
	echo '/* sysdep: -rdtsc */' > "$3"
fi
#rm -f tryrdtsc.o tryrdtsc
