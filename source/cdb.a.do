#!/bin/sh -e
# vim: set filetype=sh:
objects="cdb.o cdb_hash.o cdb_make.o"
redo-ifchange makelib ${objects}
exec ./makelib "$3" ${objects}
