#!/bin/sh -e
main="`basename "$1"`"
objects="${main}.o"
libraries="buffer.a unix.a byte.a fs.a"
redo-ifchange link ${objects} ${libraries}
exec ./link "$3" ${objects} ${libraries}
