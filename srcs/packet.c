#include "ft_nmap.h"

int	send_packet(t_socket socket, char *dataframe)
{
	if (sendto(
			socket.sfd,
			dataframe,
			sizeof(struct ip) + sizeof(struct tcphdr),
			0,
			(struct sockaddr *)&socket.sin,
			sizeof(struct sockaddr)
		) < 0)
	{
		fprintf(stderr, "Failed to send TCP packet %s\n", strerror(errno));
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}
