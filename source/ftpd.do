#!/bin/sh -e
# vim: set filetype=sh:
main="`basename "$1"`"
objects="${main}.o main.o fetch.o ip.o iopause.o"
libraries="ucspi.a publicfile.a libtai.a ndelay.a case.a stralloc.a alloc.a substdio.a sig.a env.a str.a fs.a unix.a byte.a"
redo-ifchange link ${objects} ${libraries} socket.lib
exec ./link "$3" ${objects} ${libraries} `cat socket.lib`
