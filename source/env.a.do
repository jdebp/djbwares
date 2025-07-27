#!/bin/sh -e
# vim: set filetype=sh:
objects="env.o env_read.o env_write.o"
redo-ifchange makelib ${objects}
exec ./makelib "$3" ${objects}
