#!/bin/sh -e
## **************************************************************************
## For copyright and licensing terms, see the file named COPYING.
## **************************************************************************
# vim: set filetype=sh:
objects="cdb.o cdb_hash.o cdb_make.o"
redo-ifchange makelib ${objects}
exec ./makelib "$3" ${objects}
