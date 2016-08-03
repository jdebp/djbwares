#!/bin/sh -e
case $1 in
  ptybandage|ptyrun|nobuf|ttydetach|exclon|excloff|background)
    redo-ifchange $1.1
    nroff -man $1.1 > "$3"
    ;;
  ptyget|ptyspawn|ptyio)
    redo-ifchange $1.8
    nroff -man $1.8 > "$3"
    ;;
  *)
    echo '### No such target: ' "$1"
    exit 100
    ;;
esac
