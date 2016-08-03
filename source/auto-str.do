#!/bin/sh -e
main="`basename "$1"`"
objects="${main}.o"
libraries="buffer.a unix.a str.a"
redo-ifchange link ${objects} ${libraries}
exec ./link "$3" ${objects} ${libraries}
