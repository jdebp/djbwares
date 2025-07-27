#!/bin/sh -e
# vim: set filetype=sh:
redo-ifchange tryarmcnt.c compile link
if ( ./compile tryarmcnt.o tryarmcnt.c tryarmcnt.d && ./link tryarmcnt tryarmcnt.o ) >/dev/null 2>&1
then
	echo \#define HASARMCNT 1 > "$3"
else
	echo '/* sysdep: -armcnt */' > "$3"
fi
#rm -f tryarmcnt.o tryarmcnt
