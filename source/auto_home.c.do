#!/bin/sh -e
redo-ifchange auto-str conf-home
exec ./auto-str auto_home `head -1 conf-home` > "$3"
