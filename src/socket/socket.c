#include "socket.h"
#include "typesdef.h"
#include "scan.h"

#include <stdio.h>
#include <netdb.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

static void	update_socket_port(struct sockaddr_in *socket_addr, u16 port)
{
	socket_addr->sin_port = htons(port);
}

static void	update_socket_addr(struct sockaddr_in *socket_addr, struct in_addr addr)
{
	socket_addr->sin_addr = addr;
}

void update_socket(struct sockaddr_in *socket, t_target target, u16 port)
{
	update_socket_port(socket, port);
	update_socket_addr(socket, target.addr.sin_addr);
}

bool	init_socket(t_socket *sock, int proto)
{
	sock->sfd = socket(PF_INET, SOCK_RAW, proto);
	if (sock->sfd < 0)
	{
		fprintf(stderr, "ft_nmap: failed to create raw socket: %s\n", strerror(errno));
		return true;
	}
	return false;
}

void close_socket(t_socket socket)
{
	close(socket.sfd);
}
