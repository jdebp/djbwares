#!/bin/sh -e
# vim: set filetype=sh:
objects="pathdecode.o file.o filetype.o percent.o timeoutread.o timeoutwrite.o timeoutconn.o timeoutaccept.o"
redo-ifchange makelib ${objects}
exec ./makelib "$3" ${objects}
