#!/bin/sh -e
main="`basename "$1"`"
objects="${main}.o iopause.o printrecord.o printpacket.o parsetype.o"
libraries="getopt.a dns.a libtai.a env.a buffer.a unix.a stralloc.a alloc.a byte.a fs.a"
redo-ifchange link ${objects} ${libraries}
exec ./link "$3" ${objects} ${libraries}
