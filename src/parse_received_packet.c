#include "ft_nmap.h"
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <pcap/pcap.h>

#include <stdio.h>

static void print_debug_ethernet_header(struct ether_header *eth_header)
{
	printf("Ethernet Header:\n");
	printf(" - Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
		   eth_header->ether_shost[0], eth_header->ether_shost[1],
		   eth_header->ether_shost[2], eth_header->ether_shost[3],
		   eth_header->ether_shost[4], eth_header->ether_shost[5]);
	printf(" - Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
		   eth_header->ether_dhost[0], eth_header->ether_dhost[1],
		   eth_header->ether_dhost[2], eth_header->ether_dhost[3],
		   eth_header->ether_dhost[4], eth_header->ether_dhost[5]);
	printf(" - EtherType: 0x%04x\n", ntohs(eth_header->ether_type));
}

static void print_debug_ip_header(struct ip *ip_hdr)
{
	printf("IP Header:\n");
	printf(" - Version: %d\n", ip_hdr->ip_v);
	printf(" - Header Length: %d bytes\n", ip_hdr->ip_hl * 4);
	printf(" - Type of Service: %d\n", ip_hdr->ip_tos);
	printf(" - Total Length: %d bytes\n", ntohs(ip_hdr->ip_len));
	printf(" - Identification: %d\n", ntohs(ip_hdr->ip_id));
	printf(" - Fragment Offset: %d\n", ntohs(ip_hdr->ip_off) & 0x1FFF);
	printf(" - Time to Live: %d\n", ip_hdr->ip_ttl);
	printf(" - Protocol: %d\n", ip_hdr->ip_p);
	printf(" - Header Checksum: 0x%04x\n", ntohs(ip_hdr->ip_sum));
}

static void print_debug_sll_header(struct sll_header *sll_hdr)
{
	printf("SLL Header:\n");
	printf(" - Packet Type: %d\n", ntohs(sll_hdr->sll_pkt_type));
	printf(" - Hardware Type: %d\n", ntohs(sll_hdr->sll_hatype));
	printf(" - Hardware Address Length: %d\n", ntohs(sll_hdr->sll_halen));
	printf(" - Protocol: 0x%04x\n", ntohs(sll_hdr->sll_protocol));
}

static void handle_ip_protocol(struct ip *ip_hdr)
{
	switch (ip_hdr->ip_p)
	{
	case IPPROTO_TCP:
		printf(" - TCP Packet\n");
		break;
	case IPPROTO_ICMP:
		printf(" - ICMP Packet\n");
		break;
	case IPPROTO_UDP:
		printf(" - UDP Packet\n");
		break;
	default:
		printf(" - Other Protocol: %d\n", ip_hdr->ip_p);
		break;
	}
}

static void handle_with_ethernet(const u_char *packet)
{
	struct ether_header *eth_header = (struct ether_header *)packet;
	if (ntohs(eth_header->ether_type) == ETHERTYPE_IP)
	{
		struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct ether_header));
		print_debug_ethernet_header(eth_header);
		print_debug_ip_header(ip_hdr);
		handle_ip_protocol(ip_hdr);
	}
	else
	{
		printf("Captured non-IP packet: EtherType=0x%04x\n",
			   ntohs(eth_header->ether_type));
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
	if (ntohs(sll_hdr->sll_protocol) == ETHERTYPE_IP)
	{
		struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct sll_header));
		print_debug_sll_header(sll_hdr);
		print_debug_ip_header(ip_hdr);
		handle_ip_protocol(ip_hdr);
	}
	else
	{
		printf("Captured non-IP packet: Protocol=0x%04x\n",
			   ntohs(sll_hdr->sll_protocol));
	}
}

static void parse_datalink_layer(const u_char *packet, pcap_t *handle)
{
	int datalink_type = pcap_datalink(handle);

	switch (datalink_type)
	{
	case DLT_EN10MB:
		printf("Datalink Layer: Ethernet\n");
		handle_with_ethernet(packet);
		break;
	case DLT_LINUX_SLL:
		printf("Datalink Layer: Linux SLL\n");
		handle_with_linux_sll(packet);
		break;
	case DLT_RAW:
		printf("Datalink Layer: Raw IP\n");
		handle_with_raw_ip(packet);
		break;
	case DLT_NULL:
		printf("Datalink Layer: Null/Loopback\n");
		handle_with_null_loopback(packet);
		break;
	default:
		printf("Datalink Layer: Unknown (%d)\n", datalink_type);
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
