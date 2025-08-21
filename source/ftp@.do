#!/bin/sh -e
## **************************************************************************
## For copyright and licensing terms, see the file named COPYING.
## **************************************************************************
# vim: set filetype=sh:
redo-ifchange warn-auto.sh $1.sh home
sed s}HOME}`./home`}g warn-auto.sh $1.sh > "$3"
chmod 755 $3
