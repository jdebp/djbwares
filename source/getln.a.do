#!/bin/sh -e
objects="getln.o getln2.o"
redo-ifchange makelib ${objects}
exec ./makelib "$3" ${objects}
