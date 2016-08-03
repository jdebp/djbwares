#!/bin/sh -e
objs=""
redo-ifchange link $1.o $objs
./link $3 $1.o $objs
