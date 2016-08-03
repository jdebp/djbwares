#!/bin/sh -e
objects="strerr.o strerr_die.o strerr_sys.o"
redo-ifchange makelib ${objects}
exec ./makelib "$3" ${objects}
