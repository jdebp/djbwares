#!/bin/sh -e
redo-ifchange trymkffo.c compile link
if ( ./compile trymkffo.o trymkffo.c trymkffo.d && ./link trymkffo trymkffo.o ) >/dev/null 2>&1
then
	echo \#define HASMKFIFO 1 > "$3"
else
	echo '/* sysdep: -mkfifo */' > "$3"
fi
#rm -f trymkffo.o trymkffo
