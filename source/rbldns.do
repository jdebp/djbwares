#!/bin/sh -e
main="`basename "$1"`"
objects="${main}.o server.o droproot.o response.o qlog.o dd.o"
libraries="dns.a alloc.a env.a cdb.a buffer.a unix.a byte.a fs.a"
redo-ifchange link ${objects} ${libraries} socket.lib
exec ./link "$3" ${objects} ${libraries} `cat socket.lib`
