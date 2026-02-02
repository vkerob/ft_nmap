#include "ft_nmap.h"
#include <netinet/if_ether.h>
#include <netinet/udp.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include <sys/_types/_u_char.h>
#include <sys/types.h>

// bonus: for later
// note: build with a spoofed src and dst gateway MAC address
void build_ethernet_header(struct ether_header *eth_hdr)
{
	(void)eth_hdr;
}

void build_ip_header(struct ip *ip_hdr, t_probe_request *request)
{
	(void)ip_hdr;
	(void)request;
}

void build_tcp_header(struct tcphdr *tcp_hdr, t_ip_pseudo_hdr *ip_pseudo_hdr, uint16_t destination_port)
{
	// Will be use to calculate the TCP checksum
	build_pseudo_ip_header(ip_pseudo_hdr);
	memset(tcp_hdr, 0, sizeof(struct tcphdr));
	/* Source port */
	tcp_hdr->th_sport = htons(31999);
	/* Destination port */
	tcp_hdr->th_dport = destination_port;
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

void build_udp_header(struct udphdr *udp_hdr, uint16_t dest_port)
{
	(void)udp_hdr;
	(void)dest_port;
}

void assemble_full_packet(u_char *packet, struct ether_header *eth_hdr,
						  struct ip *ip_hdr, struct tcphdr *tcp_hdr,
						  struct udphdr *udp_hdr)
{
	(void)packet;
	(void)eth_hdr;
	(void)ip_hdr;
	(void)tcp_hdr;
	(void)udp_hdr;
}

static void build_scan_packets(t_probe_request *request, u_char *packet,
							   t_shared_data *shared_data)
{
	struct ether_header	eth_hdr;
	t_ip_pseudo_hdr		ip_pseudo_hdr;
	struct ip			ip_hdr;
	struct tcphdr		tcp_hdr;
	struct udphdr		udp_hdr;
	t_socket			socket;

	init_socket(&socket);

	memset(&tcp_hdr, 0, sizeof(tcp_hdr));
	memset(&udp_hdr, 0, sizeof(udp_hdr));

	if (shared_data->gateway_mac[0] != 0)
		build_ethernet_header(&eth_hdr);

	build_ip_header(&ip_hdr, request);

	if (request->type == SCAN_SYN || request->type == SCAN_ACK
		|| request->type == SCAN_FIN || request->type == SCAN_XMAS
		|| request->type == SCAN_NULL)
	{
		build_tcp_header(&tcp_hdr, &ip_pseudo_hdr, request->target.port);
		calculate_tcp_checksum(&ip_pseudo_hdr, &tcp_hdr);
		// assemble full packet
	}
	else if (request->type == SCAN_UDP)
	{
		// build UDP header
		build_udp_header(&udp_hdr, request->target.port);
	}
	packet = (u_char *)&tcp_hdr;
	assemble_full_packet(packet, &eth_hdr, &ip_hdr, &tcp_hdr, &udp_hdr);
}

void *send_packet(void *arg)
{
	t_shared_data	*shared_data = (t_shared_data *)arg;
	u8				packet[4096];

	build_scan_packets(shared_data->request_list_tail, packet, shared_data);

	return NULL;
}
