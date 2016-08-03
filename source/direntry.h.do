#!/bin/sh -e
main="`basename "$1" .h`"
redo-ifchange choose.sh trydrent.c ${main}.h1 ${main}.h2
exec ./choose.sh c trydrent ${main}.h1 ${main}.h2 > "$3"
