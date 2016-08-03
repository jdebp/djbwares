#!/bin/sh -e
objects="alloc.o alloc_re.o getln.o getln2.o stralloc_cat.o stralloc_catb.o stralloc_cats.o stralloc_copy.o stralloc_eady.o stralloc_num.o stralloc_opyb.o stralloc_opys.o stralloc_pend.o"
redo-ifchange makelib ${objects}
exec ./makelib "$3" ${objects}
