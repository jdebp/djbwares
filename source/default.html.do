#!/bin/sh -e
src="`basename "$1"`.xml"
if test -r "${src}"
then
	mkdir -p tmp
	man="index.html"
	redo-ifchange "${src}"
	setlock tmp/index.html.lock sh -c "xmlto --skip-validation -o tmp html \"${src}\" && mv \"tmp/${man}\" \"$3\""
else
	redo-ifcreate "${src}"
	if test -r pape-manual-pages/"`basename "$1"`.1"
	then
		redo-ifchange pape-manual-pages/"`basename "$1"`.1"
		echo '<p>Pape manual page not yet converted to Docbook XML</p>' > "$3"
	else
		redo-ifcreate pape-manual-pages/"`basename "$1"`.1"
		if test -r pape-manual-pages/"`basename "$1"`.8"
		then
			redo-ifchange pape-manual-pages/"`basename "$1"`.8"
			echo '<p>Pape manual page not yet converted to Docbook XML</p>' > "$3"
		else
			redo-ifcreate pape-manual-pages/"`basename "$1"`.8"
			if test -r bernstein-manual-pages/"`basename "$1"`.1"
			then
				redo-ifchange bernstein-manual-pages/"`basename "$1"`.1"
				echo '<p>Bernstein manual page not yet converted to Docbook XML</p>' > "$3"
			else
				redo-ifcreate bernstein-manual-pages/"`basename "$1"`.1"
				if test -r bernstein-manual-pages/"`basename "$1"`.8"
				then
					redo-ifchange bernstein-manual-pages/"`basename "$1"`.8"
					echo '<p>Bernstein manual page not yet converted to Docbook XML</p>' > "$3"
				else
					redo-ifcreate bernstein-manual-pages/"`basename "$1"`.8"
					echo '<p>Bernstein manual page does not exist</p>' > "$3"
				fi
			fi
		fi
	fi
fi
