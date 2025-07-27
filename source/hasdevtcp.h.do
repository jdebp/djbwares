#!/bin/sh -e
# vim: set filetype=sh:
redo-ifchange find-systype.sh 
case "`./find-systype.sh`" in
	sunos-5.*) echo \#define HASDEVTCP 1 > "$3" ;;
	*) echo '/* sysdep: -devtcp */' > "$3" ;;
esac
