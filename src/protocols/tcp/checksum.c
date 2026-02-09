
#include "tcp.h"
#include "protocols.h"

#include <string.h>

void	calculate_tcp_checksum(
	t_ip_pseudo_hdr *ip_pseudo_hdr, struct tcphdr *tcp_hdr)
{
	char	buffer[1024];
	memset(buffer, 0, sizeof(buffer));

	memcpy(buffer, ip_pseudo_hdr, sizeof(t_ip_pseudo_hdr));
	memcpy(buffer + sizeof(t_ip_pseudo_hdr), tcp_hdr, sizeof(t_tcp_hdr));

	tcp_hdr->th_sum = calculate_checksum(
		buffer,
		(sizeof(t_tcp_hdr) + sizeof(t_ip_pseudo_hdr))
	);
}
