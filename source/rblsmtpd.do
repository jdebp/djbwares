#!/bin/sh -e
# vim: set filetype=sh:
main="`basename "$1"`"
objects="${main}.o commands.o iopause.o"
libraries="ucspi.a getopt.a dns.a libtai.a strerr.a buffer.a unix.a sig.a env.a stralloc.a alloc.a byte.a fs.a"
redo-ifchange link ${objects} ${libraries}
exec ./link "$3" ${objects} ${libraries}
