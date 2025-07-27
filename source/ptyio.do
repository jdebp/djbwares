#!/bin/sh -e
# vim: set filetype=sh:
objs="ttyctrl.o ttymodes.o"
libs="unix.a sig.a env.a getopt.a substdio.a buffer.a str.a unix.a"
redo-ifchange link $1.o $objs $libs
./link $3 $1.o $objs $libs
