#include "ft_nmap.h"

void	update_port_tcp(struct tcphdr *tcp_hdr, uint16_t port)
{
	tcp_hdr->th_dport = htons(port);
}

void calculate_tcp_checksum(t_ip_pseudo_hdr *ip_pseudo_hdr, struct tcphdr *tcp_hdr)
{
	char buffer[1014] = { 0 };

	memcpy((void *)buffer, ip_pseudo_hdr, sizeof(t_ip_pseudo_hdr));
	memcpy((void *)buffer + sizeof(t_ip_pseudo_hdr), tcp_hdr, sizeof(struct tcphdr));
	tcp_hdr->th_sum = calculate_checksum(buffer, sizeof(struct tcphdr));
	
}

void	fill_tcp_header(struct tcphdr *tcp_hdr)
{
	/* Source port */
	tcp_hdr->th_sport = htons(31999);
	/* Destination port */
	tcp_hdr->th_dport = 0;
	tcp_hdr->th_seq = 0;
	/* If ACK flag is set this is the value of the next sequence expected to receive */
	tcp_hdr->th_ack = htonl(0);
	tcp_hdr->th_x2 = 0;
	/* TCP Header length in 32 bit word */
	tcp_hdr->th_off = sizeof(*tcp_hdr) / 4;
	/* Control flags */
	tcp_hdr->th_flags = TH_SYN;
	/* Maximum size we can read in our buffer without windows scaling */
	tcp_hdr->th_win = htons(65535);
	/* Checksum */
	tcp_hdr->th_sum = 0;
	/* Set with URG flag to indicate the index where the urgent data is located */
	tcp_hdr->th_urp = 0;
}

