#!/bin/sh -e
man="`basename "$1"`.3"
if test -r pape-manual-pages/"${man}"
then
	redo-ifchange pape-manual-pages/"${man}"
	rm -f -- "$3"
	ln -- pape-manual-pages/"${man}" "$3"
elif test -r bernstein-manual-pages/"${man}"
then
	redo-ifchange bernstein-manual-pages/"${man}"
	rm -f -- "$3"
	ln -- bernstein-manual-pages/"${man}" "$3"
else
	src="`basename "$1"`.xml"
	if test -r "${src}"
	then
		mkdir -p tmp
		redo-ifchange "${src}"
		setlock tmp/index.html.lock sh -c "xmlto --skip-validation -o tmp man \"${src}\" && mv \"tmp/${man}\" \"$3\""
	else
		redo-ifcreate "${src}"
		echo '.TH' "`basename \"$1\"`" 1 > "$3"
		echo "No manual!" > "$3"
	fi
fi
