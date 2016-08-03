#!/bin/sh -e
objects="error.o error_str.o error_temp.o"
redo-ifchange makelib ${objects}
exec ./makelib "$3" ${objects}
