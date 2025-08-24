#ifndef PUBLICFILE_SERVER_H
#define PUBLICFILE_SERVER_H

#include "stralloc.h"
#include "buffer.h"

/* Common content publicfile server architecture and utilities. */

void out_put(const char *s,int len);
void out_puts(const char *s);
void out_flush(void);
void out_put_nvt(const char *s,int len);
void in_get_nvt(char *ch);
int readline2(buffer * pin, stralloc * line);
int readline(void);

extern stralloc line;

#endif
