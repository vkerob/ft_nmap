#include "ft_nmap.h"

void	decode_ip_packet(u8 *datagram, struct ip	*ip_hdr)
{
	*ip_hdr = *(struct ip *)datagram;

	ip_hdr->ip_len = ip_hdr->ip_len;
	ip_hdr->ip_id  = ntohs(ip_hdr->ip_id);
	ip_hdr->ip_sum  = ntohs(ip_hdr->ip_sum);
	ip_hdr->ip_src.s_addr = ntohl(ip_hdr->ip_src.s_addr);
	ip_hdr->ip_dst.s_addr = ntohl(ip_hdr->ip_dst.s_addr);
	ip_hdr->ip_len = ntohs(ip_hdr->ip_len);
	ip_hdr->ip_src.s_addr = ntohl((u32)ip_hdr->ip_src.s_addr);
	ip_hdr->ip_dst.s_addr = ntohl((u32)ip_hdr->ip_dst.s_addr);
}


void	fill_pseudo_ip_header(t_ip_pseudo_hdr *ip_pseudo_hdr)
{
	struct in_addr	src_addr;

	if (inet_pton(AF_INET, "192.168.64.1", &src_addr) == 0) {
		fprintf(stderr, "Invalid source address\n");
		exit(EXIT_FAILURE);
	}

	ip_pseudo_hdr->ip_src = src_addr;
	ip_pseudo_hdr->tcp_length = htons(sizeof(struct tcphdr));
	ip_pseudo_hdr->protocol = IPPROTO_TCP;
}
