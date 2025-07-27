#!/bin/sh -e
# vim: set filetype=sh:
redo-ifchange choose.sh load tryvfork.c fork.h1 fork.h2
./choose.sh cl tryvfork fork.h1 fork.h2 > "$3"
