#!/bin/sh -e
# vim: set filetype=sh:
main="`basename "$1"`"
objects="${main}.o main.o iopause.o"
libraries="ucspi.a publicfile.a libtai.a case.a getln.a stralloc.a alloc.a substdio.a buffer.a unix.a sig.a env.a str.a fs.a"
redo-ifchange link ${objects} ${libraries} socket.lib
exec ./link "$3" ${objects} ${libraries} `cat socket.lib`
