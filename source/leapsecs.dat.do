#!/bin/sh -e
## **************************************************************************
## For copyright and licensing terms, see the file named COPYING.
## **************************************************************************
# vim: set filetype=sh:
redo-ifchange leapsecs leapsecs.txt
./leapsecs < leapsecs.txt > "$3"
