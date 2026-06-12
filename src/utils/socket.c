#include "socket.h"
#include "scan.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

bool init_socket(t_socket *sock, const int proto)
{
	sock->sfd = socket(PF_INET, SOCK_RAW, proto);
	if (sock->sfd < 0)
	{
		LOG("ft_nmap: failed to create raw socket: %s\n", strerror(errno));
		return true;
	}
	const int opt = 1;
	if (setsockopt(sock->sfd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt)) == -1)
	{
		LOG("ft_nmap: %s\n", strerror(errno));
		close(sock->sfd);
		return true;
	}
	return false;
}
