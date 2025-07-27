#!/bin/sh -e
# vim: set filetype=sh:
redo-ifchange auto-str conf-home
exec ./auto-str auto_home `head -1 conf-home` > "$3"
