#!/bin/sh -e
main="`basename "$1" .h`"
redo-ifchange choose.sh tryulong64.c ${main}.h1 ${main}.h2
exec ./choose.sh clr tryulong64 ${main}.h1 ${main}.h2 > "$3"
