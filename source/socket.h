#ifndef SOCKET_H
#define SOCKET_H

#include "uint16.h"

struct ip_address;

extern int socket_tcp(const struct ip_address *);
extern int socket_udp(const struct ip_address *);

extern int socket_connect(int,const struct ip_address *,uint16);
extern int socket_connected(int);
extern int socket_bind(int,const struct ip_address *,uint16);
extern int socket_bind_reuse(int,const struct ip_address *,uint16);
extern int socket_listen(int,int);
extern int socket_accept(int,struct ip_address *,uint16 *);
extern int socket_recv(int,char *,int,struct ip_address *,uint16 *);
extern int socket_send(int,const char *,int,const struct ip_address *,uint16);
extern int socket_local(int,struct ip_address *,uint16 *);
extern int socket_remote(int,struct ip_address *,uint16 *);

extern void socket_tryreservein(int,int);

extern int socket_is_udp(int fd);
extern int socket_is_tcp(int fd);

int socket_ipoptionskill(int s);
int socket_tcpnodelay(int s);

void socket_listen_get_udptcp(const char *, int *, int *, int *, int *, uint16 *, struct ip_address *, uint16);
void socket_listen_get_udp(const char *, int *, int *, uint16 *, struct ip_address *, uint16);

#endif
