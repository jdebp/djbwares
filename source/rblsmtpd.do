#!/bin/sh -e
main="`basename "$1"`"
objects="${main}.o commands.o iopause.o ucspi.o"
libraries="getopt.a dns.a libtai.a strerr.a buffer.a unix.a sig.a env.a stralloc.a alloc.a byte.a fs.a"
redo-ifchange link ${objects} ${libraries}
exec ./link "$3" ${objects} ${libraries}
