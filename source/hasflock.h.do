#!/bin/sh -e
redo-ifchange tryflock.c compile link
if ( ./compile tryflock.o tryflock.c tryflock.d && ./link tryflock tryflock.o ) >/dev/null 2>&1 
then
	echo \#define HASFLOCK 1 > "$3"
else
	echo '/* sysdep: -flock */' > "$3"
fi
#rm -f trysgact.o trysgact
