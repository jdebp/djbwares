#!/bin/sh -e
## **************************************************************************
## For copyright and licensing terms, see the file named COPYING.
## **************************************************************************
# vim: set filetype=sh:
objects="byte_chr.o byte_copy.o byte_cr.o byte_diff.o byte_rchr.o byte_reverse.o byte_zero.o case_diffb.o case_diffs.o case_lowerb.o mem_copy.o mem_copyr.o mem_diff.o mem_reverse.o mem_zero.o str_chr.o str_diff.o str_len.o str_rchr.o str_start.o uint16_pack.o uint16_unpack.o uint32_pack.o uint32_unpack.o"
redo-ifchange makelib ${objects}
exec ./makelib "$3" ${objects}
