#!/bin/sh -e
objects="sig.o sig_block.o sig_catch.o sig_dfl.o sig_pause.o sig_pipe.o"
redo-ifchange makelib ${objects}
exec ./makelib "$3" ${objects}
