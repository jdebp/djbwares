#ifndef SOCKET_H
#define SOCKET_H

#include "uint16.h"

extern int socket_tcp(void);
extern int socket_udp(void);

extern int socket_connect4(int,const char *,uint16);
extern int socket_connected(int);
extern int socket_bind4(int,char *,uint16);
extern int socket_bind4_reuse(int,char *,uint16);
extern int socket_listen(int,int);
extern int socket_accept4(int,char *,uint16 *);
extern int socket_recv4(int,char *,int,char *,uint16 *);
extern int socket_send4(int,const char *,int,const char *,uint16);
extern int socket_local4(int,char *,uint16 *);
extern int socket_remote4(int,char *,uint16 *);

extern void socket_tryreservein(int,int);

extern int socket_is_udp(int fd);
extern int socket_is_udp4(int fd);
extern int socket_is_tcp(int fd);

int socket_ipoptionskill(int s);
int socket_tcpnodelay(int s);

#endif
