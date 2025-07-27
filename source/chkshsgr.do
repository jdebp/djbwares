#!/bin/sh -e
# vim: set filetype=sh:
main="`basename "$1"`"
objects="${main}.o"
libraries=""
redo-ifchange link ${objects} ${libraries}
exec ./link "$3" ${objects} ${libraries}
