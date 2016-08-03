#!/bin/sh -e
main="`basename "$1"`"
objects="${main}.o iopause.o"
libraries="dns.a libtai.a env.a alloc.a buffer.a unix.a byte.a fs.a"
redo-ifchange link ${objects} ${libraries} socket.lib
exec ./link "$3" ${objects} ${libraries} `cat socket.lib`
