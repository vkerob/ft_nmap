
#include "tcp.h"
#include "protocols.h"

#include <string.h>

void	calculate_tcp_checksum(const t_ip_pseudo_hdr *ip_pseudo_hdr, struct tcphdr *tcp_hdr)
{
	char	buffer[1024] = { 0 };

	memcpy(buffer, ip_pseudo_hdr, sizeof(t_ip_pseudo_hdr));
	memcpy(buffer + sizeof(t_ip_pseudo_hdr), tcp_hdr, sizeof(t_tcp_hdr));

	tcp_hdr->th_sum = calculate_checksum(
		buffer,
		sizeof(t_tcp_hdr) + sizeof(t_ip_pseudo_hdr)
	);
}
