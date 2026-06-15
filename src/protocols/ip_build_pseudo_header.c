#include "ip.h"
#include "udp.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>

int build_pseudo_ip_header(t_ip_pseudo_hdr *ip_pseudo_hdr,
							const char *dst_addr, const char *src_addr,
							u8 protocol)
{
	if (inet_pton(AF_INET, src_addr, &ip_pseudo_hdr->ip_src) != 1)
	{
		LOG("ft_nmap: invalid source address '%s'\n", src_addr);
		return FAILURE;
	}

	if (inet_pton(AF_INET, dst_addr, &ip_pseudo_hdr->ip_dst) != 1)
	{
		LOG("ft_nmap: invalid destination address '%s'\n", dst_addr);
		return FAILURE;
	}

	ip_pseudo_hdr->length = protocol == IPPROTO_TCP
								? htons(sizeof(t_tcp_hdr))
								: htons(sizeof(struct udphdr));
	ip_pseudo_hdr->protocol = protocol;
	return SUCCESS;
}
