#!/bin/sh -e
main="`basename "$1"`"
objects="${main}.o auto_home.o fifo.o"
libraries="unix.a str.a fs.a"
redo-ifchange link ${objects} ${libraries} socket.lib
exec ./link "$3" ${objects} ${libraries} `cat socket.lib`
