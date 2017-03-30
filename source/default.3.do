#!/bin/sh -e
man="`basename "$1"`.3"
src="`basename "$1"`.xml"
if test -r "${src}" && test _"leapsecs.xml" != _"${src}"
then
	mkdir -p tmp
	redo-ifchange "${src}" "version.xml"
	setlock tmp/index.html.lock sh -c "xmlto --skip-validation -o tmp man \"${src}\" && mv \"tmp/${man}\" \"$3\""
else
	if test _"leapsecs.xml" != _"${src}"
	then
		redo-ifcreate "${src}"
	fi
	if test -r pape-manual-pages/"${man}"
	then
		redo-ifchange pape-manual-pages/"${man}"
		rm -f -- "$3"
		ln -- pape-manual-pages/"${man}" "$3"
	else
		redo-ifcreate pape-manual-pages/"${man}"
		if test -r bernstein-manual-pages/"${man}"
		then
			redo-ifchange bernstein-manual-pages/"${man}"
			rm -f -- "$3"
			ln -- bernstein-manual-pages/"${man}" "$3"
		else
			redo-ifcreate bernstein-manual-pages/"${man}"
			echo '.TH' "`basename \"$1\"`" 1 > "$3"
			echo "No manual!" > "$3"
		fi
	fi
fi
