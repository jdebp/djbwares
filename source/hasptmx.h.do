#!/bin/sh -e
redo-ifchange tryptmx.c compile link
if ( ./compile tryptmx.o tryptmx.c tryptmx.d && ./link tryptmx tryptmx.o && ./tryptmx ) >/dev/null 2>&1
then
	echo \#define HASPTMX 1 > "$3"
else
	echo '/* sysdep: -ptmx */' > "$3"
fi
#rm -f tryptmx.o tryptmx
