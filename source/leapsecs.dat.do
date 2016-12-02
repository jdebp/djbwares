#!/bin/sh -e
redo-ifchange leapsecs leapsecs.txt
./leapsecs < leapsecs.txt > "$3"
