#!/bin/sh -e
## **************************************************************************
## For copyright and licensing terms, see the file named COPYING.
## **************************************************************************
# vim: set filetype=sh:
main="`basename "$1"`"
objects="${main}.o droproot.o okclient.o log.o cache.o query.o roots.o iopause.o ip.o"
libraries="dns.a ucspi.a libtai.a alloc.a env.a cdb.a buffer.a unix.a fs.a byte.a"
redo-ifchange link ${objects} ${libraries} socket.lib
exec ./link "$3" ${objects} ${libraries} `cat socket.lib`
