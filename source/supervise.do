#!/bin/sh -e
# vim: set filetype=sh:
main="`basename "$1"`"
objects="${main}.o deepsleep.o iopause.o"
libraries="libtai.a strerr.a buffer.a unix.a sig.a alloc.a byte.a fs.a"
redo-ifchange link ${objects} ${libraries}
exec ./link "$3" ${objects} ${libraries}
