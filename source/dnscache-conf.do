#!/bin/sh -e
# vim: set filetype=sh:
main="`basename "$1"`"
objects="${main}.o generic-conf.o auto_home.o"
libraries="libtai.a buffer.a unix.a byte.a"
redo-ifchange link ${objects} ${libraries}
exec ./link "$3" ${objects} ${libraries}
