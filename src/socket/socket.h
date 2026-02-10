#ifndef SOCKET_H
#define SOCKET_H

#include <netinet/in.h>

typedef struct	s_socket
{
	int									sfd;
	int									source_port;
	struct sockaddr_in	sin;
}	t_socket;

int		init_socket(t_socket *sock);
void	close_socket(t_socket socket);

#endif