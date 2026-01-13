
#include "ft_nmap.h"

void print_ip_header(struct ip *ip_hdr)
{
	printf("\nIP HEADER: \n");
	printf("version: %d\n", ip_hdr->ip_v);
	printf("ihl: %d\n", ip_hdr->ip_hl);
	printf("type of service: %d\n", ip_hdr->ip_tos);
	printf("total length %d\n", ip_hdr->ip_len);
	printf("checksum %d\n", ip_hdr->ip_sum);
	printf("id %d\n", ip_hdr->ip_id);
	printf("protocol: %d\n", ip_hdr->ip_p);
}

void print_tcp_header(struct tcphdr *tcp_hdr)
{
	printf("\nTCP HEADER: \n");
	printf("Flag: %d\n", tcp_hdr->th_flags);
	printf("Source port %d\n", ntohs(tcp_hdr->th_sport));
	printf("Destination port %d\n", ntohs(tcp_hdr->th_dport));
	printf("TCP sequence %d\n", tcp_hdr->th_seq);
	printf("Acknowlegdement number %d\n", ntohl(tcp_hdr->th_ack));
	printf("Header length %d\n", tcp_hdr->th_off);
	
	if (tcp_hdr->th_flags & TH_SYN){
		printf("SYN request");
	}
	if (tcp_hdr->th_flags & TH_ACK){
		printf("ACK request\n");
	}

	if (tcp_hdr->th_flags & TH_FIN){
		printf("FIN request\n");
	}

	printf("Window size: %d\n", ntohs(tcp_hdr->th_win));
	printf("Checksum %d\n", tcp_hdr->th_sum);
	printf("Urgent pointer %d\n", tcp_hdr->th_urp);

}

void	set_default_headers(char *dataframe)
{
	struct ip	*ip_hdr = (struct ip *)(dataframe);

	fill_ip_header(ip_hdr);
	fill_tcp_header((struct tcphdr *)(dataframe + sizeof(struct ip)));
#ifdef DEBUG
	struct tcphdr *tcp_hdr = (struct tcphdr *)(dataframe + sizeof(struct ip));
	print_ip_header(ip_hdr);
	print_tcp_header(tcp_hdr);
#endif
}
