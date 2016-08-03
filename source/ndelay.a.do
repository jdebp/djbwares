#!/bin/sh -e
objects="ndelay_on.o ndelay_off.o"
redo-ifchange makelib ${objects}
exec ./makelib "$3" ${objects}
