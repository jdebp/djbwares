#!/bin/sh -e
# vim: set filetype=sh:
objects="getln.o getln2.o"
redo-ifchange makelib ${objects}
exec ./makelib "$3" ${objects}
