#include "debug.h"
#include "defines.h"
#include "scan.h"

#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <pcap/pcap.h>

void print_debug_packet_start()
{
	printf(ANSI_COLOR_CYAN
		   "============================================\n" ANSI_COLOR_RESET);
	printf(ANSI_BOLD ANSI_COLOR_CYAN "Start of Packet\n" ANSI_COLOR_RESET);
	printf(ANSI_COLOR_CYAN
		   "============================================\n" ANSI_COLOR_RESET);
}

void print_debug_packet_end()
{
	printf(ANSI_COLOR_CYAN
		   "============================================\n" ANSI_COLOR_RESET);
	printf(ANSI_BOLD ANSI_COLOR_CYAN "End of Packet\n" ANSI_COLOR_RESET);
	printf(ANSI_COLOR_CYAN
		   "============================================\n\n" ANSI_COLOR_RESET);
}

void print_debug_ethernet_header(t_eth_hdr *eth_header)
{
	printf(ANSI_BOLD ANSI_COLOR_YELLOW "\nEthernet Header:\n" ANSI_COLOR_RESET);
	printf(ANSI_COLOR_YELLOW
		   "--------------------------------------------\n" ANSI_COLOR_RESET);
	printf(ANSI_COLOR_YELLOW
		   "  • Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n" ANSI_COLOR_RESET,
		   eth_header->ether_shost[0], eth_header->ether_shost[1],
		   eth_header->ether_shost[2], eth_header->ether_shost[3],
		   eth_header->ether_shost[4], eth_header->ether_shost[5]);
	printf(
		ANSI_COLOR_YELLOW
		"  • Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n" ANSI_COLOR_RESET,
		eth_header->ether_dhost[0], eth_header->ether_dhost[1],
		eth_header->ether_dhost[2], eth_header->ether_dhost[3],
		eth_header->ether_dhost[4], eth_header->ether_dhost[5]);
	printf(ANSI_COLOR_YELLOW "  • EtherType: 0x%04x\n" ANSI_COLOR_RESET,
		   ntohs(eth_header->ether_type));
}



// void print_debug_icmp_header(struct icmphdr *icmp_hdr)
// {
// 	printf(ANSI_BOLD ANSI_COLOR_CYAN "\nICMP Header:\n" ANSI_COLOR_RESET);
// 	printf(ANSI_COLOR_CYAN
// 		   "--------------------------------------------\n" ANSI_COLOR_RESET);
// 	printf(ANSI_COLOR_CYAN "  • Type: %d\n" ANSI_COLOR_RESET, icmp_hdr->type);
// 	printf(ANSI_COLOR_CYAN "  • Code: %d\n" ANSI_COLOR_RESET, icmp_hdr->code);
// 	printf(ANSI_COLOR_CYAN "  • Checksum: 0x%04x\n" ANSI_COLOR_RESET,
// 		   ntohs(icmp_hdr->checksum));
// }



void print_debug_protocol(int protocol)
{
	switch (protocol)
	{
		case IPPROTO_TCP:
			printf(ANSI_BOLD ANSI_COLOR_GREEN "  • TCP Packet\n" ANSI_COLOR_RESET);
			break;
		case IPPROTO_ICMP:
			printf(ANSI_BOLD ANSI_COLOR_CYAN "  • ICMP Packet\n" ANSI_COLOR_RESET);
			break;
		case IPPROTO_UDP:
			printf(ANSI_BOLD ANSI_COLOR_YELLOW "  • UDP Packet\n" ANSI_COLOR_RESET);
			break;
		default:
			printf(ANSI_COLOR_RED "  • Other Protocol: %d\n" ANSI_COLOR_RESET,
				   protocol);
			break;
	}
}

void print_debug_ethernet_type(int ether_type)
{
	if (ether_type != ETHERTYPE_IP)
	{
		printf(ANSI_COLOR_RED
			   "Captured non-IP packet: EtherType=0x%04x\n" ANSI_COLOR_RESET,
			   ether_type);
	}
}


void print_debug_datalink_type(int datalink_type)
{
	switch (datalink_type)
	{
	case DLT_EN10MB:
		printf(ANSI_BOLD ANSI_COLOR_YELLOW
			   "Datalink Layer: Ethernet\n" ANSI_COLOR_RESET);
		break;
	case DLT_LINUX_SLL:
		printf(ANSI_BOLD ANSI_COLOR_MAGENTA
			   "Datalink Layer: Linux SLL\n" ANSI_COLOR_RESET);
		break;
	case DLT_RAW:
		printf(ANSI_BOLD ANSI_COLOR_BLUE
			   "Datalink Layer: Raw IP\n" ANSI_COLOR_RESET);
		break;
	case DLT_NULL:
		printf(ANSI_BOLD ANSI_COLOR_CYAN
			   "Datalink Layer: Null/Loopback\n" ANSI_COLOR_RESET);
		break;
	default:
		printf(ANSI_COLOR_RED "Datalink Layer: Unknown (%d)\n" ANSI_COLOR_RESET,
			   datalink_type);
		break;
	}
}

void print_debug_parsing_args(t_ctx ctx)
{
	printf(ANSI_COLOR_CYAN
		   "============================================\n" ANSI_COLOR_RESET);
	printf(ANSI_BOLD ANSI_COLOR_CYAN
		   "         SCAN PARAMETERS         \n" ANSI_COLOR_RESET);
	printf(ANSI_COLOR_CYAN
		   "============================================\n" ANSI_COLOR_RESET);

	printf(ANSI_BOLD ANSI_COLOR_GREEN "Targets:\n" ANSI_COLOR_RESET);
	printf(ANSI_COLOR_GREEN
		   "--------------------------------------------\n" ANSI_COLOR_RESET);
	for (size_t i = 0; i < ctx.target_count; i++)
	{
		printf(ANSI_COLOR_GREEN "  • %s (%s)\n" ANSI_COLOR_RESET,
			   ctx.targets[i].input, ctx.targets[i].ip);
	}

	printf(ANSI_BOLD ANSI_COLOR_BLUE "\nPorts:\n" ANSI_COLOR_RESET);
	printf(ANSI_COLOR_BLUE
		   "--------------------------------------------\n" ANSI_COLOR_RESET);
	for (size_t i = 0; i < ctx.args.port_count; i++)
	{
		printf(ANSI_COLOR_BLUE "  • %u\n" ANSI_COLOR_RESET, ctx.args.ports[i]);
	}

	printf(ANSI_BOLD "\nOther parameters:\n" ANSI_COLOR_RESET);
	printf("--------------------------------------------\n");
	for (u8 i = 0; i < ctx.args.nb_scan_types; i++)
	{
		printf("%d\n", ctx.args.scan_types[i]);
	}
	printf("Speed:     " ANSI_COLOR_YELLOW "%u\n" ANSI_COLOR_RESET,
		   ctx.args.speed);
	printf("Device:    " ANSI_COLOR_YELLOW "%s\n" ANSI_COLOR_RESET,
		   ctx.dev_name);

	// Ligne de fin
	printf(ANSI_COLOR_CYAN
		   "============================================\n\n" ANSI_COLOR_RESET);
}
