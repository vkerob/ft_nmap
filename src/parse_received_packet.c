#include "ft_nmap.h"
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap/pcap.h>

static void handle_ip_protocol(struct ip *ip_hdr)
{
	void *protocol_hdr;

	protocol_hdr = (void *)((u_char *)ip_hdr + ip_hdr->ip_hl * 4);
	print_debug_protocol(ip_hdr->ip_p);

	switch (ip_hdr->ip_p)
	{
	case IPPROTO_TCP:
	{
		struct tcphdr *tcp_hdr = (struct tcphdr *)protocol_hdr;
		print_debug_tcp_header(tcp_hdr);
		break;
	}
	case IPPROTO_ICMP:
	{
		// struct icmphdr *icmp_hdr = (struct icmphdr *)protocol_hdr;
		// print_debug_icmp_header(icmp_hdr);
		break;
	}
	case IPPROTO_UDP:
	{
		struct udphdr *udp_hdr = (struct udphdr *)protocol_hdr;
		print_debug_udp_header(udp_hdr);
		
		break;
	}
	default:
		break;
	}
}

static void handle_with_ethernet(const u_char *packet)
{
	struct ether_header *eth_header = (struct ether_header *)packet;
	print_debug_ethernet_type(ntohs(eth_header->ether_type));

	if (ntohs(eth_header->ether_type) == ETHERTYPE_IP)
	{
		struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct ether_header));
		print_debug_ethernet_header(eth_header);
		print_debug_ip_header(ip_hdr);
		handle_ip_protocol(ip_hdr);
	}
}

static void handle_with_raw_ip(const u_char *packet)
{
	struct ip *ip_hdr = (struct ip *)packet;
	print_debug_ip_header(ip_hdr);
	handle_ip_protocol(ip_hdr);
}

static void handle_with_null_loopback(const u_char *packet)
{
	struct ip *ip_hdr = (struct ip *)packet;
	print_debug_ip_header(ip_hdr);
	handle_ip_protocol(ip_hdr);
}

static void handle_with_linux_sll(const u_char *packet)
{
	struct sll_header *sll_hdr = (struct sll_header *)packet;
	print_debug_sll_protocol(ntohs(sll_hdr->sll_protocol));

	if (ntohs(sll_hdr->sll_protocol) == ETHERTYPE_IP)
	{
		struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct sll_header));
		print_debug_sll_header(sll_hdr);
		print_debug_ip_header(ip_hdr);
		handle_ip_protocol(ip_hdr);
	}
}

static void parse_datalink_layer(const u_char *packet, pcap_t *handle)
{
	printf("parse datalink layer\n");
	int datalink_type = pcap_datalink(handle);
	print_debug_datalink_type(datalink_type);

	switch (datalink_type)
	{
	case DLT_EN10MB:
		printf("DLT_EN10MB\n");
		handle_with_ethernet(packet);
		break;
	case DLT_LINUX_SLL:
		printf("DLT_LINUX_SLL\n");
		handle_with_linux_sll(packet);
		break;
	case DLT_RAW:
		printf("DLT_RAW\n");
		handle_with_raw_ip(packet);
		break;
	case DLT_NULL:
		printf("DLT_NULL\n");
		handle_with_null_loopback(packet);
		break;
	default:
		printf("default\n");
		break;
	}
}

void handle_packet(u_char *args, const struct pcap_pkthdr *header,
				   const u_char *packet)
{
	(void)args;
	(void)header;
	t_pcap_user_data *user_data = (t_pcap_user_data *)args;
	pcap_t			 *handle = user_data->handle;

	parse_datalink_layer(packet, handle);
}
