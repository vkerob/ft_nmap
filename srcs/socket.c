#include "ft_nmap.h"

int	init_socket(t_socket *sock)
{
	struct protoent	*proto;
	
	proto = getprotobyname("tcp");
	if (!proto) {
		fprintf(stderr, "Invalid protocol name");
		return EXIT_FAILURE;
	}

	sock->sfd = socket(PF_INET, SOCK_RAW, proto->p_proto);
	if (sock->sfd < 0) {
		fprintf(stderr, "Error creating socket %s\n", strerror(errno));
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

void close_socket(t_socket *socket)
{
	close(socket->sfd);
}