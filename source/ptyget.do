#!/bin/sh -e
objs="strerr.a buffer.a unix.a env.a alloc.a fs.a str.a"
redo-ifchange link $1.o $objs
./link $3 $1.o $objs
