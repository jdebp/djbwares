#!/bin/sh -e
redo-ifchange trygethr.c compile link
if ( ./compile trygethr.o trygethr.c trygethr.d && ./link trygethr trygethr.o ) >/dev/null 2>&1
then
	echo \#define HASGETHRTIME 1 > "$3"
else
	echo '/* sysdep: -gethrtime */' > "$3"
fi
#rm -f trygethr.o trygethr
