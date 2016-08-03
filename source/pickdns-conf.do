#!/bin/sh -e
main="`basename "$1"`"
objects="${main}.o generic-conf.o auto_home.o"
libraries="buffer.a unix.a byte.a"
redo-ifchange link ${objects} ${libraries}
exec ./link "$3" ${objects} ${libraries}
