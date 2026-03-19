#include "socket.h"
#include "scan.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void update_socket_port(struct sockaddr_in *socket_addr, u16 port)
{
	socket_addr->sin_port = htons(port);
}

static void update_socket_addr(struct sockaddr_in *socket_addr,
							   struct in_addr	   addr)
{
	socket_addr->sin_addr = addr;
}

void update_socket(struct sockaddr_in *socket, t_target target, u16 port)
{
	update_socket_port(socket, port);
	update_socket_addr(socket, target.addr);
}

bool init_socket(t_socket *sock, const int proto)
{
	sock->sfd = socket(PF_INET, SOCK_RAW, proto);
	if (sock->sfd < 0)
	{
		fprintf(stderr, "ft_nmap: failed to create raw socket: %s\n",
				strerror(errno));
		return true;
	}
	const int opt = 1;
	if (setsockopt(sock->sfd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt)) == -1)
	{
		fprintf(stderr, "ft_nmap: %s\n",
				strerror(errno));
		return true;
	}
	return false;
}

