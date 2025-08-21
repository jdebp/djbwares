#!/bin/sh -e
## **************************************************************************
## For copyright and licensing terms, see the file named COPYING.
## **************************************************************************
# vim: set filetype=sh:
main="`basename "$1"`"
objects="${main}.o iopause.o droproot.o tdlookup.o qlog.o ip.o"
libraries="ucspi.a publicfile.a dns.a libtai.a alloc.a env.a cdb.a buffer.a unix.a byte.a fs.a"
redo-ifchange link ${objects} ${libraries}
exec ./link "$3" ${objects} ${libraries}
