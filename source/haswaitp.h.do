#!/bin/sh -e
redo-ifchange trywaitp.c compile link
if ( ./compile trywaitp.o trywaitp.c trywaitp.d && ./link trywaitp trywaitp.o ) >/dev/null 2>&1
then
	echo \#define HASWAITPID 1 > "$3"
else
	echo '/* sysdep: -waitpid */' > "$3"
fi
