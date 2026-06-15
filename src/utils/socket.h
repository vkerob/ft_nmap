#ifndef SOCKET_H
#define SOCKET_H

#include "scan.h"

#include <netinet/in.h>

typedef struct	s_socket
{
	int									sfd;
	struct sockaddr_in	sin;
}	t_socket;

int	init_socket(t_socket *sock, int proto);

#endif
