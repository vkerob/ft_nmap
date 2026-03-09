#include "tcp.h"

void	decode_tcp_packet(u8 *datagram, struct tcphdr *tcp_hdr)
{
	*tcp_hdr = *(struct tcphdr *)datagram;
	tcp_hdr->th_sport = ntohs(tcp_hdr->th_sport);
	tcp_hdr->th_dport = ntohs(tcp_hdr->th_dport);
	tcp_hdr->th_ack = ntohl(tcp_hdr->th_ack);
	tcp_hdr->th_win = ntohs(tcp_hdr->th_win);
	tcp_hdr->th_sum = ntohs(tcp_hdr->th_sum);
};
