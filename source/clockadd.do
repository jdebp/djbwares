#!/bin/sh -e
main="`basename "$1"`"
objects="${main}.o"
libraries="strerr.a buffer.a str.a unix.a"
redo-ifchange link ${objects} ${libraries} socket.lib
exec ./link "$3" ${objects} ${libraries} `cat socket.lib`
