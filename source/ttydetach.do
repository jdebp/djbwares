#!/bin/sh -e
objs="ttyctrl.o strerr.a buffer.a env.a alloc.a str.a unix.a"
redo-ifchange link $1.o $objs
./link $3 $1.o $objs
