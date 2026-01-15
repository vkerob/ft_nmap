#include "ft_nmap.h"


void print_ip_header(struct ip *ip_hdr)
{
	printf("\nIP HEADER: \n");
	printf("version: %d\n", ip_hdr->ip_v);
	printf("ihl: %d\n", ip_hdr->ip_hl);
	printf("type of service: %d\n", ip_hdr->ip_tos);
	printf("total length %d\n", ip_hdr->ip_len);
	printf("id %d\n", ip_hdr->ip_id);
	printf("fragment offset ? %d\n", ip_hdr->ip_off);
	printf("ttl %d\n", ip_hdr->ip_ttl);
	printf("protocol: %d\n", ip_hdr->ip_p);
	printf("checksum %02x\n", ip_hdr->ip_sum );
}

t_ethernet_hdr	decode_ethernet_packet(uint8_t *datagram)
{
	
}

struct ip	decode_ip_packet(uint8_t *datagram)
{
	struct ip	ip_hdr = *(struct ip *)datagram;
	ip_hdr.ip_len = htons(ip_hdr.ip_len);
	return ip_hdr;
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
