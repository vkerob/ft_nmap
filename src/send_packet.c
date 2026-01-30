#include "ft_nmap.h"
#include <netinet/if_ether.h>
#include <netinet/udp.h>
#include <pcap/pcap.h>
#include <pthread.h>
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

void build_tcp_header(struct tcphdr *tcp_hdr, uint16_t dest_port)
{
	(void)tcp_hdr;
	(void)dest_port;
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
	struct ether_header eth_hdr;
	struct ip			ip_hdr;
	struct tcphdr		tcp_hdr;
	struct udphdr		udp_hdr;

	memset(&tcp_hdr, 0, sizeof(tcp_hdr));
	memset(&udp_hdr, 0, sizeof(udp_hdr));

	if (shared_data->gateway_mac[0] != 0)
		build_ethernet_header(&eth_hdr);

	build_ip_header(&ip_hdr, request);

	if (request->type == SCAN_SYN || request->type == SCAN_ACK
		|| request->type == SCAN_FIN || request->type == SCAN_XMAS
		|| request->type == SCAN_NULL)
	{
		build_tcp_header(&tcp_hdr, request->target.port);
		// assemble full packet
	}
	else if (request->type == SCAN_UDP)
	{
		// build UDP header
		build_udp_header(&udp_hdr, request->target.port);
	}

	assemble_full_packet(packet, &eth_hdr, &ip_hdr, &tcp_hdr, &udp_hdr);
}

void *send_packet(void *arg)
{
	t_shared_data *shared_data = (t_shared_data *)arg;
	u_char		   packet[4096];

	build_scan_packets(shared_data->request_list_tail, packet, shared_data);
	// send packet using raw socket

	return NULL;
}