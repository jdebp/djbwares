#!/bin/sh -e
main="`basename "$1" .h`"
redo-ifchange choose.sh tryulong32.c ${main}.h1 ${main}.h2
exec ./choose.sh clr tryulong32 ${main}.h1 ${main}.h2 > "$3"
