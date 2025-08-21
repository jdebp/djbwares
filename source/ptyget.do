#!/bin/sh -e
## **************************************************************************
## For copyright and licensing terms, see the file named COPYING.
## **************************************************************************
# vim: set filetype=sh:
objs="strerr.a buffer.a unix.a env.a alloc.a fs.a str.a"
redo-ifchange link $1.o $objs
./link $3 $1.o $objs
