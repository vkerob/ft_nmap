
#include "ft_nmap.h"

void print_tcp_header(struct tcphdr *tcp_hdr)
{
	printf("\nTCP HEADER: \n");
	// printf("Flag: %d\n", tcp_hdr->th_flags);
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

void	set_default_headers(char *datagram, t_ip_pseudo_hdr *ip_pseudo_hdr)
{
	fill_pseudo_ip_header(ip_pseudo_hdr);
	fill_tcp_header((struct tcphdr *)(datagram));
#ifdef DEBUG
	struct tcphdr *tcp_hdr = (struct tcphdr *)(datagram);
	print_tcp_header(tcp_hdr);
#endif
}
