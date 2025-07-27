#ifndef SOCKET_H
#define SOCKET_H

#include "uint16.h"

extern int socket_tcp4(void);
extern int socket_tcp6(void);
extern int socket_udp4(void);
extern int socket_udp6(void);

extern int socket_connect4(int,const char [4],uint16);
extern int socket_connect6(int,const char [20],uint16);
extern int socket_connected(int);
extern int socket_bind4(int,char [4],uint16);
extern int socket_bind6(int,char [20],uint16);
extern int socket_bind4_reuse(int,char [4],uint16);
extern int socket_bind6_reuse(int,char [20],uint16);
extern int socket_listen(int,int);
extern int socket_accept4(int,char [4],uint16 *);
extern int socket_accept6(int,char [20],uint16 *);
extern int socket_recv4(int,char *,int,char [4],uint16 *);
extern int socket_recv6(int,char *,int,char [20],uint16 *);
extern int socket_send4(int,const char *,int,const char [4],uint16);
extern int socket_send6(int,const char *,int,const char [20],uint16);
extern int socket_local4(int,char [4],uint16 *);
extern int socket_local6(int,char [20],uint16 *);
extern int socket_remote4(int,char [4],uint16 *);
extern int socket_remote6(int,char [20],uint16 *);

extern void socket_tryreservein(int,int);

extern int socket_is_udp(int fd);
extern int socket_is_udp4(int fd);
extern int socket_is_udp6(int fd);
extern int socket_is_tcp(int fd);
extern int socket_is_tcp4(int fd);
extern int socket_is_tcp6(int fd);

int socket_ipoptionskill(int s);
int socket_tcpnodelay(int s);

void socket_listen_get_udp4(const char *, int *, int *, uint16 *, char [4], uint16);
void socket_listen_get_udptcp4(const char *, int *, int *, int *, int *, uint16 *, char [4], uint16);
void socket_listen_get_udp6(const char *, int *, int *, uint16 *, char [20], uint16);

#endif
