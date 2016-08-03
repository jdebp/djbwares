#!/bin/sh -e
objects="fmt_str.o fmt_strn.o fmt_uint.o fmt_uint0.o fmt_ushort.o fmt_ulong.o fmt_xlong.o fmt_xdigit.o scan_ulong.o scan_xdigit.o scan_xlong.o ip4_fmt.o ip4_scan.o ip6_fmt.o ip6_scan.o"
redo-ifchange makelib ${objects}
exec ./makelib "$3" ${objects}
