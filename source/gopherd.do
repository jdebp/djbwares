#!/bin/sh -e
main="`basename "$1"`"
objects="${main}.o main.o pathdecode.o file.o filetype.o httpdate.o percent.o timeoutread.o timeoutwrite.o iopause.o ucspi.o"
libraries="libtai.a case.a getln.a stralloc.a alloc.a substdio.a buffer.a unix.a sig.a env.a str.a fs.a"
redo-ifchange link ${objects} ${libraries} socket.lib
exec ./link "$3" ${objects} ${libraries} `cat socket.lib`
