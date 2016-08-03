#!/bin/sh -e
result="$4"

redo-ifchange "$3" "$4"
case "$1" in
  *c*) 
	redo-ifchange compile "$2.c"
	./compile "$2.o" "$2.c" "$2.d" >/dev/null 2>&1 || result="$3" 
	;;
esac

case "$1" in
  *l*) 
	redo-ifchange load
	./load "$2" >/dev/null 2>&1 || result="$3" 
	;;
esac

case "$1" in
  *r*) 
	"./$2" >/dev/null 2>&1 || result="$3" 
	;;
esac

exec cat "$result"
