#include "ft_nmap.h"


void	fill_pseudo_ip_header(t_ip_pseudo_hdr *ip_pseudo_hdr)
{

	struct in_addr	src_addr;

	if (inet_pton(AF_INET, "192.168.64.1", &src_addr) == 0) {
		fprintf(stderr, "Invalid source address\n");
		exit(EXIT_FAILURE);
	}
	// ip_hdr->ip_src = src_addr;

	ip_pseudo_hdr->ip_src = src_addr;
	ip_pseudo_hdr->tcp_length = htons(sizeof(struct tcphdr));
	ip_pseudo_hdr->protocol = IPPROTO_TCP;
}
