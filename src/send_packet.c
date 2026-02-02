#include "ft_nmap.h"
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/types.h>

#define IP_VERSION 4
#define IP_IHL 5
#define IP_TTL_DEFAULT 64

// bonus: for later
// note: build with a spoofed src and dst gateway MAC address
void build_ethernet_header(struct ether_header *eth_hdr)
{
	(void)eth_hdr;
	eth_hdr->ether_type = htons(ETHERTYPE_IP);
}

void build_ip_header(struct ip *ip_hdr, t_probe_request *request,
					 char *source_ip, _Atomic uint16_t *id_counter)
{
	(void)ip_hdr;
	(void)request;
	ip_hdr->ip_v = IP_VERSION;
	ip_hdr->ip_hl = IP_IHL;
	ip_hdr->ip_ttl = IP_TTL_DEFAULT;
	ip_hdr->ip_p = (request->type == SCAN_UDP) ? IPPROTO_UDP : IPPROTO_TCP;
	ip_hdr->ip_len = htons(sizeof(struct ip));

	// for ip_off htons(0x4000) sets the DF (Don't Fragment) flag but it's
	// poossible to be rejected by some firewalls
	ip_hdr->ip_off = 0;
	ip_hdr->ip_id = htons(atomic_fetch_add(id_counter, 1));
	ip_hdr->ip_sum = calculate_checksum(ip_hdr, ip_hdr->ip_hl * 4);
	ip_hdr->ip_src.s_addr = inet_addr(source_ip);
	ip_hdr->ip_dst.s_addr = inet_addr(request->target.ip);
	// no priority
	ip_hdr->ip_tos = 0;
}

void build_tcp_header(struct tcphdr *tcp_hdr, uint16_t dest_port,
					  _Atomic uint32_t *base_port)
{
	(void)tcp_hdr;
	(void)dest_port;
	tcp_hdr->th_off = 5; // data offset: size of tcp header in 32-bit words
	tcp_hdr->th_flags = TH_SYN;
	(void)base_port;
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

	build_ip_header(&ip_hdr, request, shared_data->source_ip, &shared_data->id);

	if (request->type == SCAN_SYN || request->type == SCAN_ACK
		|| request->type == SCAN_FIN || request->type == SCAN_XMAS
		|| request->type == SCAN_NULL)
	{
		build_tcp_header(&tcp_hdr, request->target.port,
						 &shared_data->base_port);
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