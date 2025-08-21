#!/bin/sh -e
## **************************************************************************
## For copyright and licensing terms, see the file named COPYING.
## **************************************************************************
# vim: set filetype=sh:
objs=""
redo-ifchange link $1.o $objs
./link $3 $1.o $objs
