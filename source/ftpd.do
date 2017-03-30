#!/bin/sh -e
main="`basename "$1"`"
objects="${main}.o main.o pathdecode.o file.o fetch.o ip.o timeoutread.o timeoutwrite.o timeoutconn.o timeoutaccept.o iopause.o ucspi.o"
libraries="libtai.a ndelay.a case.a stralloc.a alloc.a substdio.a sig.a env.a str.a fs.a unix.a byte.a"
redo-ifchange link ${objects} ${libraries} socket.lib
exec ./link "$3" ${objects} ${libraries} `cat socket.lib`
