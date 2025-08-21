#!/bin/sh -e
## **************************************************************************
## For copyright and licensing terms, see the file named COPYING.
## **************************************************************************
# vim: set filetype=sh:
if test -n "${USE_INHERITED_COMPILER_VARIABLES}"
then
	# Bypass for some packagers.
	# If you set the wrong libraries, features, include paths, or language level you are on your own.
	cppflags="${CPPFLAGS}"
	cxxflags="${CXXFLAGS}"
	ldflags="${LDFLAGS}"
	ccflags="${CCFLAGS}"
	cxx="${CXX}"
	cc="${CC}"
else
	# Normal auto-detection path.
	cppflags="-I . ${kqueue}"
	ldflags="-g -pthread"
	if command -v >/dev/null clang++
	then
		cc="clang"
		ccflags="-g -pthread -std=gnu11 -Os -Weverything -Wno-conversion -Wno-sign-conversion -Wno-c99-compat -Wno-missing-prototypes -Wno-weak-vtables -Wno-packed -Wno-padded -Wpacked -Wno-exit-time-destructors -Wno-global-constructors -Wno-documentation-unknown-command -Wno-zero-length-array -Wno-non-virtual-dtor -integrated-as"
		cxx="clang++"
		cxxflags="-g -pthread -std=gnu++11 -Os -Weverything -Wno-conversion -Wno-sign-conversion -Wno-c++98-compat -Wno-c++98-compat-pedantic -Wno-missing-prototypes -Wno-weak-vtables -Wno-packed -Wno-padded -Wpacked -Wno-exit-time-destructors -Wno-global-constructors -Wno-documentation-unknown-command -Wno-zero-length-array -Wno-non-virtual-dtor -integrated-as"
	elif test "_`uname`" = _OpenBSD && command -v >/dev/null eg++
	then
		cc="egcc"
		ccflags="-g -Wall -Wextra"
		cxx="eg++"
		cxxflags="-g -Wall -Wextra"
	elif command -v >/dev/null g++
	then
		cc="gcc"
		ccflags="-g -Wall -Wextra"
		cxx="g++"
		cxxflags="-g -Wall -Wextra"
	elif command -v >/dev/null owcc
	then
		cc="owcc"
		ccflags="-g -Wall -Wextra -Wc,-xs -Wc,-xr"
		cxx="owcc"
		cxxflags="-g -Wall -Wextra -Wc,-xs -Wc,-xr"
	elif command -v >/dev/null owcc.exe
	then
		cc="owcc.exe"
		ccflags="-g -Wall -Wextra -Wc,-xs -Wc,-xr"
		cxx="owcc.exe"
		cxxflags="-g -Wall -Wextra -Wc,-xs -Wc,-xr"
	else
		echo "Cannot find clang++, g++, or owcc." 1>&2
		exit 100
	fi
fi
case "`basename "$1"`" in
cc)
	echo "$cc" > "$3"
	;;
cxx)
	echo "$cxx" > "$3"
	;;
cppflags)
	echo "$cppflags" > "$3"
	;;
ccflags)
	echo "$ccflags" > "$3"
	;;
cxxflags)
	echo "$cxxflags" > "$3"
	;;
ldflags)
	echo "$ldflags" > "$3"
	;;
*)
	echo 1>&2 "$1: No such target."
	exit 111
	;;
esac
true
