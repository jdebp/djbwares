#!/bin/sh -e
objects0="taia_tai.o"
objects1="tai_add.o tai_uint.o tai_now.o tai_pack.o tai_sub.o tai_unpack.o taia_add.o taia_approx.o taia_frac.o taia_half.o taia_less.o taia_now.o taia_pack.o taia_unpack.o taia_sub.o taia_uint.o"
objects2="caldate_fmjd.o caltime_utc.o leapsecs_init.o leapsecs_read.o leapsecs_add.o leapsecs_sub.o"
redo-ifchange makelib ${objects1} ${objects2}
exec ./makelib "$3" ${objects1} ${objects2}
