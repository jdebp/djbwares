#!/bin/sh -e
objs="getopt.a sig.a env.a strerr.a getopt.a buffer.a str.a unix.a"
redo-ifchange link $1.o $objs
./link $3 $1.o $objs
