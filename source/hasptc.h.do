#!/bin/sh -e
redo-ifchange tryptc.c compile link
if ( ./compile tryptc.o tryptc.c tryptc.d && ./link tryptc tryptc.o && ./tryptc ) >/dev/null 2>&1
then
	echo \#define HASPTC 1 > "$3"
else
	echo '/* sysdep: -ptc */' > "$3"
fi
#rm -f tryptc.o tryptc
