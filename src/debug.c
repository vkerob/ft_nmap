// #include "ft_nmap.h"

// void	print_eth_header(t_ethernet_hdr *eth_hdr)
// {
// 	printf("\nETHERNET HEADER: \n");
// 	printf("Destination MAC: ");
// 	for (int i = 0; i < 6; i++)
// 	{
// 		printf("%02x", eth_hdr->dst_mac_addr[i]);
// 		if (i != 5)
// 			printf(":");
// 	}
// 	printf("\n");
// 	printf("Source MAC: ");
// 	for (int i = 0; i < 6; i++)
// 	{
// 		printf("%02x", eth_hdr->src_mac_addr[i]);
// 		if (i != 5)
// 			printf(":");
// 	}
// 	printf("\n");
// 	printf("Protocol (EtherType): 0x%04x\n", ntohs(eth_hdr->protocol));
// }

// void	print_ip_header(struct ip *ip_hdr)
// {
// 	printf("\nIP HEADER: \n");
// 	printf("Version: %d\n", ip_hdr->ip_v);
// 	printf("IHL: %d (words) / %d (bytes)\n", ip_hdr->ip_hl, ip_hdr->ip_hl * 4);
// 	printf("Type of Service: %d\n", ip_hdr->ip_tos);
// 	printf("Total length: %d\n", ntohs(ip_hdr->ip_len));
// 	printf("ID: %d\n", ntohs(ip_hdr->ip_id));
// 	printf("Fragment offset/flags: 0x%04x\n", ntohs(ip_hdr->ip_off));
// 	printf("TTL: %d\n", ip_hdr->ip_ttl);
// 	printf("Protocol: %d\n", ip_hdr->ip_p);
// 	printf("Checksum: 0x%04x\n", ntohs(ip_hdr->ip_sum));
// 	printf("Source: %s\n", inet_ntoa(ip_hdr->ip_src));
// 	printf("Destination: %s\n", inet_ntoa(ip_hdr->ip_dst));
// }

// void	print_tcp_header(struct tcphdr *tcp_hdr)
// {
// 	printf("\nTCP HEADER: \n");
// 	printf("Source port: %d\n", tcp_hdr->th_sport);
// 	printf("Destination port: %d\n", tcp_hdr->th_dport);
// 	printf("Sequence number: %u\n", (unsigned)tcp_hdr->th_seq);
// 	printf("Acknowledgement: %u\n", (unsigned)tcp_hdr->th_ack);
// 	printf("Header length: %d (words) / %d (bytes)\n",
// 		tcp_hdr->th_off, tcp_hdr->th_off * 4);

// 	printf("Flags: ");
// 	if (tcp_hdr->th_flags & TH_URG) printf("URG ");
// 	if (tcp_hdr->th_flags & TH_ACK) printf("ACK ");
// 	if (tcp_hdr->th_flags & TH_PUSH) printf("PUSH ");
// 	if (tcp_hdr->th_flags & TH_RST) printf("RST ");
// 	if (tcp_hdr->th_flags & TH_SYN) printf("SYN ");
// 	if (tcp_hdr->th_flags & TH_FIN) printf("FIN ");
// 	printf("\n");

// 	printf("Window size: %d\n", tcp_hdr->th_win);
// 	printf("Checksum: 0x%04x\n", tcp_hdr->th_sum);
// 	printf("Urgent pointer: %d\n", tcp_hdr->th_urp);
// }

// void print_headers(
// 	t_ethernet_hdr *eth_hdr, struct ip *ip_hdr, struct tcphdr *tcp_hdr
// )
// {
// (void)tcp_hdr;
// 	print_eth_header(eth_hdr);
// 	print_ip_header(ip_hdr);
// 	// print_tcp_header(tcp_hdr);
// }
