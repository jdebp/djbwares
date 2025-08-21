#!/bin/sh -e
## **************************************************************************
## For copyright and licensing terms, see the file named COPYING.
## **************************************************************************
# vim: set filetype=sh:
objects="error.o error_str.o error_temp.o"
redo-ifchange makelib ${objects}
exec ./makelib "$3" ${objects}
