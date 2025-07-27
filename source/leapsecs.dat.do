#!/bin/sh -e
# vim: set filetype=sh:
redo-ifchange leapsecs leapsecs.txt
./leapsecs < leapsecs.txt > "$3"
