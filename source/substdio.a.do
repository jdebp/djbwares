#!/bin/sh -e
# vim: set filetype=sh:
objects="substdio.o substdi.o substdo.o substdio_copy.o subfdin.o subfdout.o subfderr.o"
redo-ifchange makelib ${objects}
exec ./makelib "$3" ${objects}
