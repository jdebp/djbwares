#!/bin/sh -e
main="`basename "$1"`"
objects="${main}.o ip.o"
libraries="libtai.a strerr.a buffer.a substdio.a str.a fs.a unix.a"
redo-ifchange link ${objects} ${libraries} socket.lib
exec ./link "$3" ${objects} ${libraries} `cat socket.lib`
