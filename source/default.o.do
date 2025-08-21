#!/bin/sh -e
## **************************************************************************
## For copyright and licensing terms, see the file named COPYING.
## **************************************************************************
# vim: set filetype=sh:
src="`basename "$1"`.c"
redo-ifchange compile "${src}"
exec ./compile "$3" "${src}" "$1.d"
