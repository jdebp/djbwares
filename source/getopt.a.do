#!/bin/sh -e
objects="sgetopt.o subgetopt.o"
redo-ifchange makelib ${objects}
exec ./makelib "$3" ${objects}
