#!/bin/sh -e
man="index.html"
src="`basename "$1"`.xml"
install -d tmp
redo-ifchange "${src}"
exec setlock tmp/index.html.lock sh -c "xmlto --skip-validation -o tmp html \"${src}\" && mv \"tmp/${man}\" \"$3\""
