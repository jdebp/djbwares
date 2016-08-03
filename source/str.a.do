#!/bin/sh -e
objects="byte_chr.o byte_copy.o byte_cr.o byte_diff.o byte_rchr.o byte_zero.o str_chr.o str_diff.o str_diffn.o str_len.o str_cpy.o str_rchr.o str_start.o"
redo-ifchange makelib ${objects}
exec ./makelib "$3" ${objects}
