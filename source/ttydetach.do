#!/bin/sh -e
# vim: set filetype=sh:
objs="ttyctrl.o strerr.a buffer.a env.a alloc.a str.a unix.a"
redo-ifchange link $1.o $objs
./link $3 $1.o $objs
