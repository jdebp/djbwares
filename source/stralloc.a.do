#!/bin/sh -e
## **************************************************************************
## For copyright and licensing terms, see the file named COPYING.
## **************************************************************************
# vim: set filetype=sh:
objects="stralloc_cat.o stralloc_catb.o stralloc_cats.o stralloc_copy.o stralloc_eady.o stralloc_opyb.o stralloc_opys.o stralloc_pend.o stralloc_num.o"
redo-ifchange makelib ${objects}
exec ./makelib "$3" ${objects}
