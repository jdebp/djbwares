#!/bin/sh -e
main="`basename "$1"`"
objects="${main}.o rules.o remoteinfo.o timeoutconn.o iopause.o"
libraries="getopt.a buffer.a cdb.a env.a dns.a libtai.a unix.a stralloc.a alloc.a sig.a byte.a fs.a"
redo-ifchange link ${objects} ${libraries} socket.lib
exec ./link "$3" ${objects} ${libraries} `cat socket.lib`
