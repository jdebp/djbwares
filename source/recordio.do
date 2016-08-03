#!/bin/sh -e
main="`basename "$1"`"
objects="${main}.o iopause.o"
libraries="libtai.a buffer.a unix.a env.a sig.a stralloc.a alloc.a byte.a fs.a"
redo-ifchange link ${objects} ${libraries}
exec ./link "$3" ${objects} ${libraries}
