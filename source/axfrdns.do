#!/bin/sh -e
main="`basename "$1"`"
objects="${main}.o iopause.o droproot.o tdlookup.o response.o qlog.o timeoutread.o timeoutwrite.o ucspi.o"
libraries="dns.a libtai.a alloc.a env.a cdb.a buffer.a unix.a byte.a fs.a"
redo-ifchange link ${objects} ${libraries}
exec ./link "$3" ${objects} ${libraries}
