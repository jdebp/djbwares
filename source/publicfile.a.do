#!/bin/sh -e
## **************************************************************************
## For copyright and licensing terms, see the file named COPYING.
## **************************************************************************
# vim: set filetype=sh:
objects="pathdecode.o file.o filetype.o conf.o percent.o timeoutread.o timeoutwrite.o timeoutconn.o timeoutaccept.o"
redo-ifchange makelib ${objects}
exec ./makelib "$3" ${objects}
