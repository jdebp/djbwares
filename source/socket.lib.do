#!/bin/sh -e
redo-ifchange trylsock.o load
if ./load trylsock -lsocket -lnsl && ./trylsock 
then
	echo -lsocket -lnsl > "$3"
elif ./load trylsock -lsocket && ./trylsock 
then
	echo -lsocket > "$3"
elif ./load trylsock -lnsl && ./trylsock 
then
	echo -lnsl > "$3"
else
	echo > "$3"
fi
