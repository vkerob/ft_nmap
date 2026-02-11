#ifndef SOCKET_H
#define SOCKET_H

#include "scan.h"

#include <netinet/in.h>

typedef struct	s_socket
{
	int									sfd;
	int									source_port;
	struct sockaddr_in	sin;
}	t_socket;

bool	init_socket(t_socket *sock, u8 proto);

void	close_socket(t_socket socket);

#endif
