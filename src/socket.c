#include "ft_nmap.h"

static void	update_socket_port(struct sockaddr_in *socket_addr, u16 port)
{
	socket_addr->sin_port = htons(port);
}


static void	update_socket_addr(struct sockaddr_in *socket_addr, struct in_addr addr)
{
	socket_addr->sin_addr = addr;
}

void	update_socket(struct sockaddr_in *socket, t_target target, u16 port)
{
	update_socket_port(socket, port);
	update_socket_addr(socket, target.addr);
}

int	init_socket(t_socket *sock)
{
	struct protoent	*proto;
	
	proto = getprotobyname("tcp");
	if (!proto)
	{
		fprintf(stderr, "Invalid protocol name");
		return EXIT_FAILURE;
	}

	sock->sfd = socket(PF_INET, SOCK_RAW, proto->p_proto);
	if (sock->sfd < 0)
	{
		fprintf(stderr, "Error creating socket %s\n", strerror(errno));
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

void	close_socket(t_socket socket)
{
	close(socket.sfd);
}
