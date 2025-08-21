#!/bin/sh -e
## **************************************************************************
## For copyright and licensing terms, see the file named COPYING.
## **************************************************************************
# vim: set filetype=sh:
main="`basename "$1" .h`"
redo-ifchange choose.sh trypoll.c ${main}.h1 ${main}.h2
exec ./choose.sh c trypoll ${main}.h1 ${main}.h2 > "$3"
