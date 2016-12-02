#!/bin/sh -e
(
	echo auto_home.h 
	echo uint64.h 
	echo uint32.h 
	echo select.h 
	echo fork.h 
	echo iopause.h 
	echo hasflock.h 
	echo hasgethr.h 
	echo hasmkffo.h 
	echo haspsx.h 
	echo hasptc.h 
	echo hasptmx.h 
	echo hasrdtsc.h 
	echo hasdevtcp.h 
	echo hassgact.h 
	echo hassgprm.h 
	echo hasshsgr.h 
	echo haswaitp.h 
	echo direntry.h
	echo leapsecs.dat
	redo-ifchange ../package/headers
	cat ../package/headers |
	while read i
	do 
		echo "$i.h" 
	done
	redo-ifchange ../package/libraries
	cat ../package/libraries |
	while read i
	do 
		echo "$i.a" 
	done
	redo-ifchange ../package/commands1 
	cat ../package/commands1 | 
	while read i
	do 
		echo "$i" 
		echo "$i.1" 
		echo "$i.html"
	done 
	redo-ifchange ../package/commands8 
	cat ../package/commands8 | 
	while read i
	do 
		echo "$i" 
		echo "$i.8" 
		echo "$i.html"
	done
	redo-ifchange ../package/extra-manpages1 
	cat ../package/extra-manpages1 |
	while read i
	do 
		echo "$i.1" 
		echo "$i.html"
	done
	redo-ifchange ../package/extra-manpages3 
	cat ../package/extra-manpages3 |
	while read i
	do 
		echo "$i.3" 
		echo "$i.html"
	done
	redo-ifchange ../package/extra-manpages8
	cat ../package/extra-manpages8 |
	while read i
	do 
		echo "$i.8" 
		echo "$i.html"
	done
) | xargs redo-ifchange --
