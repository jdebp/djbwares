#!/bin/sh -e
# vim: set filetype=sh:
objects="sgetopt.o subgetopt.o"
redo-ifchange makelib ${objects}
exec ./makelib "$3" ${objects}
