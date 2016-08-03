#!/bin/sh -e
main="`basename "$1"`"
objects="${main}.o droproot.o okclient.o log.o cache.o query.o response.o dd.o roots.o iopause.o"
libraries="dns.a libtai.a alloc.a env.a cdb.a buffer.a unix.a byte.a fs.a"
redo-ifchange link ${objects} ${libraries} socket.lib
exec ./link "$3" ${objects} ${libraries} `cat socket.lib`
