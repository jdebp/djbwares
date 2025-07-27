#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "byte.h"
#include "socket.h"

int socket_local6(int s,char ip[20],uint16 *port)
{
	struct sockaddr_in6 sa;
	socklen_t dummy = sizeof sa;

	if (getsockname(s,(struct sockaddr *) &sa,&dummy) == -1) return -1;
	byte_copy(ip,16,&sa.sin6_addr);
	byte_copy(ip+16,4,&sa.sin6_scope_id);
	uint16_unpack_big((char *) &sa.sin6_port,port);
	return 0;
}
