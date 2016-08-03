#!/bin/sh -e
redo-ifchange choose.sh trysysel.c select.h1 select.h2
./choose.sh c trysysel select.h2 select.h1 > "$3"
