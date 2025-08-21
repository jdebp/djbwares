#!/bin/sh -e
## **************************************************************************
## For copyright and licensing terms, see the file named COPYING.
## **************************************************************************
# vim: set filetype=sh:
objects="socket_listenx.o ucspi.o"
redo-ifchange makelib ${objects}
exec ./makelib "$3" ${objects}
