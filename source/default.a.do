#!/bin/sh -e
if test -r "$1.use"
then
  redo-ifchange "$1.use"
  redo-ifchange makelib `cat "$1.use"`
  ./makelib "$3" `cat "$1.use"`
else
    echo '### No such target: ' "$1"
    exit 100
fi
