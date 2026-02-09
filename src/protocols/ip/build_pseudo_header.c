#include "ip.h"

#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>

void	build_pseudo_ip_header(
	t_ip_pseudo_hdr *ip_pseudo_hdr,
	const char *dst_addr,
	const char *src_addr)
{
(void)src_addr;
	if (inet_pton(AF_INET, "192.168.64.1", &ip_pseudo_hdr->ip_src) == 0) {
		fprintf(stderr, "Invalid source address\n");
		exit(EXIT_FAILURE);
	}

	if (inet_pton(AF_INET, dst_addr, &ip_pseudo_hdr->ip_dst) == 0) {
		fprintf(stderr, "Invalid source address\n");
		exit(EXIT_FAILURE);
	}

	ip_pseudo_hdr->tcp_length = htons(sizeof(t_tcp_hdr));
	ip_pseudo_hdr->protocol = IPPROTO_TCP;
}
