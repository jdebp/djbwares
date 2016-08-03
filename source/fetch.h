#ifndef FETCH_H
#define FETCH_H

#define FETCH_RETR 0
#define FETCH_NLST 1
#define FETCH_LIST 2
#define FETCH_LISTONE 3

extern void fetch(char *,int,int,int);
extern int fetch_ascii;
extern unsigned long fetch_rest;

#endif
