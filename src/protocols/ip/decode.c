#include "ip.h"

void	decode_ip_packet(u8 *datagram, t_ip *ip_hdr)
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

