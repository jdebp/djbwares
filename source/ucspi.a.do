#!/bin/sh -e
# vim: set filetype=sh:
objects="socket_listenx.o ucspi.o"
redo-ifchange makelib ${objects}
exec ./makelib "$3" ${objects}
