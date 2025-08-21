#!/bin/sh -e
## **************************************************************************
## For copyright and licensing terms, see the file named COPYING.
## **************************************************************************
# vim: set filetype=sh:
objects="sig.o sig_block.o sig_catch.o sig_dfl.o sig_pause.o sig_pipe.o"
redo-ifchange makelib ${objects}
exec ./makelib "$3" ${objects}
