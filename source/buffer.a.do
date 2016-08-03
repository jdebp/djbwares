#!/bin/sh -e
objects="makelib buffer.o buffer_0.o buffer_1.o buffer_2.o buffer_copy.o buffer_get.o buffer_put.o strerr_die.o strerr_sys.o"
redo-ifchange makelib ${objects}
exec ./makelib "$3" ${objects}
