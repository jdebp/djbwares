#!/bin/sh -e
## **************************************************************************
## For copyright and licensing terms, see the file named COPYING.
## **************************************************************************
# vim: set filetype=sh:
objects="ndelay_on.o ndelay_off.o"
redo-ifchange makelib ${objects}
exec ./makelib "$3" ${objects}
