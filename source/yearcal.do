#!/bin/sh -e
main="`basename "$1"`"
objects="${main}.o"
libraries="libtai.a strerr.a substdio.a buffer.a str.a fs.a unix.a"
redo-ifchange link ${objects} ${libraries}
exec ./link "$3" ${objects} ${libraries}
