#!/bin/sh -e
objs="substdio.a str.a unix.a auto_home.o"
redo-ifchange link $1.o $objs
./link $3 $1.o $objs
