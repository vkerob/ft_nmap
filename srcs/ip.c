#include "ft_nmap.h"

void	update_ip_headers_dst_addr(struct ip *ip_hdr, t_ip_pseudo_hdr *ip_pseudo_hdr, struct in_addr dst_addr)
{
	ip_hdr->ip_dst = dst_addr;
	ip_pseudo_hdr->ip_dst = dst_addr;
}

//void update_ip_checksum(struct ip *ip_hdr, char *buffer)
//{
//	(void)ip_hdr;
//	(void)buffer;
//	//ip_hdr->ip_sum = calculate_checksum(buffer, ip_hdr->ip_len >> 1);
//}

void	fill_ip_headers(struct ip *ip_hdr, t_ip_pseudo_hdr *ip_pseudo_hdr)
{
	struct in_addr	src_addr;

	/* Version of the IP Header */
	ip_hdr->ip_v = 4;
	/* Header length in 32 bit word */
	ip_hdr->ip_hl = 5;
	ip_hdr->ip_tos = 0;
	/* Total length of the IP Header + TCP Header */
	ip_hdr->ip_len = sizeof(struct ip) + sizeof(struct tcphdr);
	/* Checksum which is computed after the TCP header is filled */
	ip_hdr->ip_sum = 0;
	ip_hdr->ip_id = htons(9021);
	/* Value of the next level protocol */
	ip_hdr->ip_p = IPPROTO_TCP;
	/* Number of router the datagram can go through */
	ip_hdr->ip_ttl = 50;
	/* Filled later */
	ip_hdr->ip_sum = 0;
	if (inet_pton(AF_INET, "192.168.64.1", &src_addr) == 0) {
		fprintf(stderr, "Invalid source address\n");
		exit(EXIT_FAILURE);
	}
	ip_hdr->ip_src = src_addr;

	ip_pseudo_hdr->ip_src = src_addr;
	ip_pseudo_hdr->tcp_length = sizeof(struct tcphdr);
	ip_pseudo_hdr->protocol = IPPROTO_TCP;
	printf("pseudo header size: %zu\n", sizeof(t_ip_pseudo_hdr));
}

