#!/bin/sh -e
## **************************************************************************
## For copyright and licensing terms, see the file named COPYING.
## **************************************************************************
# vim: set filetype=sh:
objects="case_diffs.o case_lowerb.o case_startb.o"
redo-ifchange makelib ${objects}
exec ./makelib "$3" ${objects}
