#!/bin/sh -e
main="`basename "$1"`"
objects="${main}.o deepsleep.o iopause.o timestamp.o match.o"
libraries="getopt.a libtai.a strerr.a buffer.a unix.a env.a sig.a alloc.a byte.a fs.a"
redo-ifchange link ${objects} ${libraries}
exec ./link "$3" ${objects} ${libraries}
