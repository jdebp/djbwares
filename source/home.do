#!/bin/sh -e
## **************************************************************************
## For copyright and licensing terms, see the file named COPYING.
## **************************************************************************
# vim: set filetype=sh:
objs="substdio.a str.a unix.a auto_home.o"
redo-ifchange link $1.o $objs
./link $3 $1.o $objs
