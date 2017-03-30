#!/bin/sh -e
main="`basename "$1"`"
objects="${main}.o auto_home.o file.o ucspi.o"
libraries="strerr.a buffer.a substdio.a env.a str.a unix.a"
redo-ifchange link ${objects} ${libraries} socket.lib
exec ./link "$3" ${objects} ${libraries} `cat socket.lib`
