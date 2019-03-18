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
	redo-ifchange ../package/headers
	cat ../package/headers |
	while read i
	do 
		echo "$i.h" 
	done
) | xargs redo-ifchange --verbose --
(
	echo leapsecs.dat
	redo-ifchange ../package/libraries
	cat ../package/libraries |
	while read i
	do 
		echo "$i.a" 
	done
	for section in 1 3 5 8
	do
		redo-ifchange ../package/commands${section} 
		cat ../package/commands${section} | 
		while read i
		do 
			echo "$i" 
			echo "$i.${section}" 
			echo "$i.html"
			echo "$i.xml"
		done 
		redo-ifchange ../package/extra-manpages${section} 
		cat ../package/extra-manpages${section} |
		while read i
		do 
			test _"$i" != _leapsecs || test _"${section}" != _3 || continue
			echo "$i.${section}" 
			echo "$i.html"
			echo "$i.xml"
		done
	done
) | xargs redo-ifchange --
