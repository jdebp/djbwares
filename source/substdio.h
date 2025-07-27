#ifndef SUBSTDIO_H
#define SUBSTDIO_H

typedef struct substdio {
  char *x;
  int p;
  int n;
  int fd;
  long (*op)();
} substdio;

#define SUBSTDIO_FDBUF(op,fd,buf,len) { (buf), 0, (len), (fd), (op) }

extern void substdio_fdbuf(struct substdio *s,long (*op)(),int fd,char *buf,int len);

extern int substdio_flush(struct substdio *);
extern int substdio_put(struct substdio *,const char *,int);
extern int substdio_bput(struct substdio *,const char *,int);
extern int substdio_putflush(struct substdio *,const char *,int);
extern int substdio_puts(struct substdio *,const char *);
extern int substdio_bputs(struct substdio *,const char *);
extern int substdio_putsflush(struct substdio *,const char *);

extern int substdio_get(struct substdio *,char *,int);
extern int substdio_bget(struct substdio *,char *,int);
extern int substdio_feed(struct substdio *);

extern char *substdio_peek(const struct substdio *);
extern void substdio_seek(struct substdio *,int);

#define substdio_fileno(s) ((s)->fd)

#define SUBSTDIO_INSIZE 8192
#define SUBSTDIO_OUTSIZE 8192

#define substdio_PEEK(s) ( (s)->x + (s)->n )
#define substdio_SEEK(s,len) ( ( (s)->p -= (len) ) , ( (s)->n += (len) ) )

#define substdio_BPUTC(s,c) \
  ( ((s)->n != (s)->p) \
    ? ( (s)->x[(s)->p++] = (c), 0 ) \
    : substdio_bput((s),&(c),1) \
  )

extern int substdio_copy(struct substdio *ssout,struct substdio *ssin);

#endif
