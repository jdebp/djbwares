#!/bin/sh -e
## **************************************************************************
## For copyright and licensing terms, see the file named COPYING.
## **************************************************************************
# vim: set filetype=sh:
redo-ifchange choose.sh load tryvfork.c fork.h1 fork.h2
./choose.sh cl tryvfork fork.h1 fork.h2 > "$3"
