#!/bin/sh -e
## **************************************************************************
## For copyright and licensing terms, see the file named COPYING.
## **************************************************************************
# vim: set filetype=sh:
redo-ifchange auto-str conf-home
exec ./auto-str auto_home `head -1 conf-home` > "$3"
