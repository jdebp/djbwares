#!/bin/sh -e
objs="strerr.a buffer.a alloc.a str.a unix.a"
redo-ifchange link $1.o $objs
./link $3 $1.o $objs
