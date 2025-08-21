#!/bin/sh -e
## **************************************************************************
## For copyright and licensing terms, see the file named COPYING.
## **************************************************************************
# vim: set filetype=sh:
objects="strerr.o strerr_die.o strerr_sys.o"
redo-ifchange makelib ${objects}
exec ./makelib "$3" ${objects}
