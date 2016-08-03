#!/bin/sh -e
objects="case_diffs.o case_lowerb.o case_startb.o"
redo-ifchange makelib ${objects}
exec ./makelib "$3" ${objects}
