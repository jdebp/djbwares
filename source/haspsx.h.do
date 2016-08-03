#!/bin/sh -e
redo-ifchange trypsx.c compile link
if ( ./compile trypsx.o trypsx.c trypsx.d && ./link trypsx trypsx.o && ./trypsx ) >/dev/null 2>&1
then
	echo \#define HAS_POSIX_PTMX 1 > "$3"
else
	echo '/* sysdep: -posix_ptmx */' > "$3"
fi
#rm -f trypsx.o trypsx
