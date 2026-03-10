#include "debug.h"
#include "defines.h"
#include "ip.h"
#include "scan.h"
#include "sll.h"
#include "udp.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/socket.h>

pthread_mutex_t printf_mutex = PTHREAD_MUTEX_INITIALIZER;

void sync_printf(const char *format, ...)
{
	va_list args;
	va_start(args, format);

	pthread_mutex_lock(&printf_mutex);
	vprintf(format, args);
	pthread_mutex_unlock(&printf_mutex);

	va_end(args);
}

void print_debug_capture_thread_startup(pthread_t phid)
{
	pthread_mutex_lock(&printf_mutex);
	printf(ANSI_COLOR_CYAN
		   "============================================\n" ANSI_COLOR_RESET);
	printf(ANSI_COLOR_RED
		   "Thread %lu enter capture_routine()\n" ANSI_COLOR_RESET,
		   (unsigned long)phid);
	printf(ANSI_COLOR_CYAN
		   "============================================\n\n" ANSI_COLOR_RESET);
	pthread_mutex_unlock(&printf_mutex);
}

void print_debug_capture_thread_leave(pthread_t phid)
{
	pthread_mutex_lock(&printf_mutex);
	printf(ANSI_COLOR_CYAN
		   "============================================\n" ANSI_COLOR_RESET);
	printf(ANSI_COLOR_RED
		   "Thread %lu leave capture_routine()\n" ANSI_COLOR_RESET,
		   (unsigned long)phid);
	printf(ANSI_COLOR_CYAN
		   "============================================\n\n" ANSI_COLOR_RESET);
	pthread_mutex_unlock(&printf_mutex);
}

void print_debug_sender_thread_startup(pthread_t phid)
{
	pthread_mutex_lock(&printf_mutex);
	printf(ANSI_COLOR_CYAN
		   "============================================\n" ANSI_COLOR_RESET);
	printf(ANSI_COLOR_RED "Thread %lu enter send_routine()\n" ANSI_COLOR_RESET,
		   (unsigned long)phid);
	printf(ANSI_COLOR_CYAN
		   "============================================\n\n" ANSI_COLOR_RESET);
	pthread_mutex_unlock(&printf_mutex);
}

void print_debug_sender_thread_leave(pthread_t phid)
{
	pthread_mutex_lock(&printf_mutex);
	printf(ANSI_COLOR_CYAN
		   "============================================\n" ANSI_COLOR_RESET);
	printf(ANSI_COLOR_RED "Thread %lu leave send_routine()\n" ANSI_COLOR_RESET,
		   (unsigned long)phid);
	printf(ANSI_COLOR_CYAN
		   "============================================\n\n" ANSI_COLOR_RESET);
	pthread_mutex_unlock(&printf_mutex);
}

void print_debug_sender_thread_proceed_probe(pthread_t phid, t_probe *request,
											 struct timeval *tv)
{
	pthread_mutex_lock(&printf_mutex);
	printf(ANSI_COLOR_CYAN
		   "============================================\n" ANSI_COLOR_RESET);
	printf(ANSI_COLOR_RED
		   "Thread %lu sent probe at %ld.%06u: \n" ANSI_COLOR_RESET,
		   (unsigned long)phid, tv->tv_sec, (unsigned int)tv->tv_usec);
	printf(ANSI_COLOR_RED "  • Destination Port: %d\n" ANSI_COLOR_RESET,
		   request->port);
	printf(ANSI_COLOR_RED "  • Destination IP: %s\n" ANSI_COLOR_RESET,
		   inet_ntoa(request->target->addr));
	printf(ANSI_COLOR_CYAN
		   "============================================\n\n" ANSI_COLOR_RESET);
	pthread_mutex_unlock(&printf_mutex);
}

void print_debug_udp_header(t_udp_hdr *udp_hdr)
{
	printf(ANSI_BOLD ANSI_COLOR_YELLOW "\nUDP Header:\n" ANSI_COLOR_RESET);
	printf(ANSI_COLOR_YELLOW
		   "--------------------------------------------\n" ANSI_COLOR_RESET);
	printf(ANSI_COLOR_YELLOW "  • Source Port: %d\n" ANSI_COLOR_RESET,
		   ntohs(udp_hdr->uh_sport));
	printf(ANSI_COLOR_YELLOW "  • Destination Port: %d\n" ANSI_COLOR_RESET,
		   ntohs(udp_hdr->uh_dport));
	printf(ANSI_COLOR_YELLOW "  • Length: %d bytes\n" ANSI_COLOR_RESET,
		   ntohs(udp_hdr->uh_ulen));
	printf(ANSI_COLOR_YELLOW "  • Checksum: 0x%04x\n" ANSI_COLOR_RESET,
		   ntohs(udp_hdr->uh_sum));
}

void print_debug_tcp_header(t_tcp_hdr *tcp_hdr)
{
	printf(ANSI_BOLD ANSI_COLOR_GREEN "\nTCP Header:\n" ANSI_COLOR_RESET);
	printf(ANSI_COLOR_GREEN
		   "--------------------------------------------\n" ANSI_COLOR_RESET);
	printf(ANSI_COLOR_GREEN "  • Source Port: %d\n" ANSI_COLOR_RESET,
		   ntohs(tcp_hdr->th_sport));
	printf(ANSI_COLOR_GREEN "  • Destination Port: %d\n" ANSI_COLOR_RESET,
		   ntohs(tcp_hdr->th_dport));
	printf(ANSI_COLOR_GREEN "  • Sequence Number: %u\n" ANSI_COLOR_RESET,
		   ntohl(tcp_hdr->th_seq));
	printf(ANSI_COLOR_GREEN "  • Acknowledgment Number: %u\n" ANSI_COLOR_RESET,
		   ntohl(tcp_hdr->th_ack));
	printf(ANSI_COLOR_GREEN "  • Header Length: %d bytes\n" ANSI_COLOR_RESET,
		   tcp_hdr->th_off * 4);
	printf(ANSI_COLOR_GREEN "  • Flags: ");
	if (tcp_hdr->th_flags & TH_URG)
		printf("URG ");
	if (tcp_hdr->th_flags & TH_ACK)
		printf("ACK ");
	if (tcp_hdr->th_flags & TH_PUSH)
		printf("PUSH ");
	if (tcp_hdr->th_flags & TH_RST)
		printf("RST ");
	if (tcp_hdr->th_flags & TH_SYN)
		printf("SYN ");
	if (tcp_hdr->th_flags & TH_FIN)
		printf("FIN ");
	if (tcp_hdr->th_flags & 0x00)
		printf("None");

	printf("\n" ANSI_COLOR_RESET);

	printf(ANSI_COLOR_GREEN "  • Window Size: %d\n" ANSI_COLOR_RESET,
		   ntohs(tcp_hdr->th_win));
	printf(ANSI_COLOR_GREEN "  • Checksum: 0x%04x\n" ANSI_COLOR_RESET,
		   ntohs(tcp_hdr->th_sum));
	printf(ANSI_COLOR_GREEN "  • Urgent Pointer: %d\n" ANSI_COLOR_RESET,
		   ntohs(tcp_hdr->th_urp));
}

void print_debug_sll_header(t_sll_hdr *sll_hdr)
{
	printf(ANSI_BOLD ANSI_COLOR_MAGENTA "\nSLL Header:\n" ANSI_COLOR_RESET);
	printf(ANSI_COLOR_MAGENTA
		   "--------------------------------------------\n" ANSI_COLOR_RESET);
	printf(ANSI_COLOR_MAGENTA "  • Packet Type: %d\n" ANSI_COLOR_RESET,
		   ntohs(sll_hdr->sll_pkt_type));
	printf(ANSI_COLOR_MAGENTA "  • Hardware Type: %d\n" ANSI_COLOR_RESET,
		   ntohs(sll_hdr->sll_hatype));
	printf(ANSI_COLOR_MAGENTA
		   "  • Hardware Address Length: %d\n" ANSI_COLOR_RESET,
		   ntohs(sll_hdr->sll_halen));
	printf(ANSI_COLOR_MAGENTA "  • Protocol: 0x%04x\n" ANSI_COLOR_RESET,
		   ntohs(sll_hdr->sll_protocol));
}

void print_debug_sll_protocol(int protocol)
{
	if (protocol != ETHERTYPE_IP)
	{
		printf(ANSI_COLOR_RED
			   "Captured non-IP packet: Protocol=0x%04x\n" ANSI_COLOR_RESET,
			   protocol);
	}
}

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

void print_debug_probe_request(t_probe *request)
{
	char buf[16] = { 0 };

	printf(ANSI_COLOR_CYAN
		   "============================================\n" ANSI_COLOR_RESET);
	printf(ANSI_BOLD ANSI_COLOR_CYAN "New Probe Request:\n" ANSI_COLOR_RESET);
	printf(ANSI_COLOR_GREEN
		   "--------------------------------------------\n" ANSI_COLOR_RESET);
	printf(ANSI_COLOR_GREEN "  • Target: %s:%u\n" ANSI_COLOR_RESET,
		   inet_ntoa(request->target->addr), request->port);
	scan_type_to_str(request->type, buf);
	printf(ANSI_COLOR_YELLOW "  • Scan type: %s\n", buf);

	printf(ANSI_COLOR_GREEN "  • ID: %u\n" ANSI_COLOR_RESET, request->id);
	printf(ANSI_COLOR_GREEN "  • Retries: %u\n" ANSI_COLOR_RESET,
		   request->retries);
	printf(ANSI_COLOR_GREEN "  • Status: %u\n" ANSI_COLOR_RESET,
		   request->status);
	printf(ANSI_COLOR_GREEN "  • Interface: %s\n" ANSI_COLOR_RESET,
		   request->target->iface_info->name);
	printf(ANSI_COLOR_GREEN "  • IP src Address: %s\n" ANSI_COLOR_RESET,
		   inet_ntoa(request->target->iface_info->ip_addr));
	printf(ANSI_COLOR_GREEN "  • iface index: %u\n" ANSI_COLOR_RESET,
		   request->target->iface_info->iface_index);
	printf(ANSI_COLOR_CYAN
		   "============================================\n" ANSI_COLOR_RESET);
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

void print_debug_ip_header(struct ip *ip_hdr)
{
	printf(ANSI_BOLD ANSI_COLOR_BLUE "\nIP Header:\n" ANSI_COLOR_RESET);
	printf(ANSI_COLOR_BLUE
		   "--------------------------------------------\n" ANSI_COLOR_RESET);
	printf(ANSI_COLOR_BLUE "  • Source IP: %s\n" ANSI_COLOR_RESET,
		   inet_ntoa(ip_hdr->ip_src));
	printf(ANSI_COLOR_BLUE "  • Destination IP: %s\n" ANSI_COLOR_RESET,
		   inet_ntoa(ip_hdr->ip_dst));
	printf(ANSI_COLOR_BLUE "  • Version: %d\n" ANSI_COLOR_RESET, ip_hdr->ip_v);
	printf(ANSI_COLOR_BLUE "  • Header Length: %d bytes\n" ANSI_COLOR_RESET,
		   ip_hdr->ip_hl * 4);
	printf(ANSI_COLOR_BLUE "  • Type of Service: %d\n" ANSI_COLOR_RESET,
		   ip_hdr->ip_tos);
	printf(ANSI_COLOR_BLUE "  • Total Length: %d bytes\n" ANSI_COLOR_RESET,
		   ntohs(ip_hdr->ip_len));
	printf(ANSI_COLOR_BLUE "  • Identification: %d\n" ANSI_COLOR_RESET,
		   ntohs(ip_hdr->ip_id));
	printf(ANSI_COLOR_BLUE "  • Fragment Offset: %d\n" ANSI_COLOR_RESET,
		   ntohs(ip_hdr->ip_off) & 0x1FFF);
	printf(ANSI_COLOR_BLUE "  • Time to Live: %d\n" ANSI_COLOR_RESET,
		   ip_hdr->ip_ttl);
	printf(ANSI_COLOR_BLUE "  • Protocol: %d\n" ANSI_COLOR_RESET, ip_hdr->ip_p);
	printf(ANSI_COLOR_BLUE "  • Header Checksum: 0x%04x\n" ANSI_COLOR_RESET,
		   ntohs(ip_hdr->ip_sum));
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
			   ctx.targets[i].input, inet_ntoa(ctx.targets[i].addr));
	}

	printf(ANSI_BOLD ANSI_COLOR_BLUE "\nPorts:\n" ANSI_COLOR_RESET);
	printf(ANSI_COLOR_BLUE
		   "--------------------------------------------\n" ANSI_COLOR_RESET);
	for (size_t i = 0; i < ctx.args.port_count; i++)
	{
		printf(ANSI_COLOR_BLUE "  • %u\n" ANSI_COLOR_RESET, ctx.args.ports[i]);
	}
	printf(ANSI_BOLD ANSI_COLOR_CYAN
		   "\nScans to be performed:\n" ANSI_COLOR_RESET);
	printf(ANSI_COLOR_CYAN
		   "--------------------------------------------\n" ANSI_COLOR_RESET);

	// for (u8 i = 0; i < ctx.args.nb_scan_types; i++)
	// {
	// 	scan_type_to_str(ctx.args.scan_types[i]);
	// }
	printf(ANSI_BOLD "\nOther parameters:\n" ANSI_COLOR_RESET);
	printf("--------------------------------------------\n");
	printf("Speed:     " ANSI_COLOR_YELLOW "%u\n" ANSI_COLOR_RESET,
		   ctx.args.speed);

	// Ligne de fin
	printf(ANSI_COLOR_CYAN
		   "============================================\n\n" ANSI_COLOR_RESET);
}

void print_debug_iface_info(t_iface_info *ifaces, size_t iface_count)
{
	printf(ANSI_COLOR_CYAN
		   "============================================\n" ANSI_COLOR_RESET);
	printf(ANSI_BOLD ANSI_COLOR_CYAN
		   "         INTERFACES INFO         \n" ANSI_COLOR_RESET);
	printf(ANSI_COLOR_CYAN
		   "============================================\n" ANSI_COLOR_RESET);

	for (size_t i = 0; i < iface_count; i++)
	{
		printf(ANSI_BOLD ANSI_COLOR_YELLOW "Interface %zu:\n" ANSI_COLOR_RESET,
			   i + 1);
		printf(ANSI_COLOR_YELLOW "  • Name: %s\n" ANSI_COLOR_RESET,
			   ifaces[i].name);
	}

	printf(ANSI_COLOR_CYAN
		   "============================================\n\n" ANSI_COLOR_RESET);
}

void print_debug_receiver_data(t_receiver_data *receiver_data)
{
	printf(ANSI_COLOR_CYAN
		   "============================================\n" ANSI_COLOR_RESET);
	printf(ANSI_BOLD ANSI_COLOR_CYAN " SHARED DATA PCAP \n" ANSI_COLOR_RESET);
	printf(ANSI_COLOR_CYAN
		   "============================================\n" ANSI_COLOR_RESET);
	printf(ANSI_BOLD ANSI_COLOR_BLUE "PCAP Handle:\n" ANSI_COLOR_RESET);
	printf(ANSI_COLOR_BLUE " • %p\n" ANSI_COLOR_RESET,
		   (void *)receiver_data->handle);
	printf(ANSI_BOLD ANSI_COLOR_BLUE "\nsent Request List:\n" ANSI_COLOR_RESET);
	printf(ANSI_COLOR_BLUE " • Head: %p\n" ANSI_COLOR_RESET,
		   (void *)receiver_data->to_send->head);
	printf(ANSI_COLOR_BLUE " • Tail: %p\n" ANSI_COLOR_RESET,
		   (void *)receiver_data->to_send->tail);
	printf(ANSI_BOLD ANSI_COLOR_BLUE
		   "\nsent Request List Mutex:\n" ANSI_COLOR_RESET);
	printf(ANSI_BOLD ANSI_COLOR_BLUE " • %p\n" ANSI_COLOR_RESET,
		   (void *)&receiver_data->to_send->mut);
	printf(ANSI_COLOR_CYAN
		   "============================================\n\n" ANSI_COLOR_RESET);
}

void print_debug_shared_data_probe(t_shared_data_sender *shared_data_probe,
								   t_iface_info			*ifaces)
{
	sync_printf(
		ANSI_COLOR_CYAN
		"============================================\n" ANSI_COLOR_RESET);
	sync_printf(ANSI_BOLD ANSI_COLOR_CYAN
				" SHARED DATA PROBE \n" ANSI_COLOR_RESET);
	sync_printf(
		ANSI_COLOR_CYAN
		"============================================\n" ANSI_COLOR_RESET);
	sync_printf(ANSI_BOLD ANSI_COLOR_MAGENTA
				"Number of interface: \n" ANSI_COLOR_RESET);
	sync_printf(ANSI_COLOR_MAGENTA " • %zu\n" ANSI_COLOR_RESET,
				shared_data_probe->iface_count);
	sync_printf(ANSI_BOLD ANSI_COLOR_MAGENTA
				"Number of ports to scan:\n" ANSI_COLOR_RESET);
	sync_printf(ANSI_COLOR_MAGENTA " • %d\n" ANSI_COLOR_RESET,
				shared_data_probe->port_count);
	sync_printf(ANSI_COLOR_MAGENTA
				"Number of probe to send: \n" ANSI_COLOR_RESET);
	sync_printf(ANSI_COLOR_MAGENTA " • %d\n" ANSI_COLOR_RESET,
				shared_data_probe->to_send.nb_probe);
	sync_printf(ANSI_BOLD ANSI_COLOR_MAGENTA
				"Queue of probe to send:\n" ANSI_COLOR_RESET);
	sync_printf(ANSI_COLOR_MAGENTA " • %p\n" ANSI_COLOR_RESET,
				(void *)&shared_data_probe->to_send);
	sync_printf(
		ANSI_BOLD ANSI_COLOR_MAGENTA
		"\nQueues of sent probe (one per interface):\n" ANSI_COLOR_RESET);
	for (size_t i = 0; i < shared_data_probe->iface_count; i++)
	{
		sync_printf(ANSI_COLOR_MAGENTA
					"	• Queue of %s interface\n" ANSI_COLOR_RESET,
					ifaces[i].name);
		sync_printf(ANSI_COLOR_MAGENTA
					"	• Queue address: %p\n" ANSI_COLOR_RESET,
					(void *)&shared_data_probe->sent[i]);
		sync_printf(ANSI_COLOR_MAGENTA
					"	• Queue mutex: %p\n" ANSI_COLOR_RESET,
					(void *)&shared_data_probe->sent[i].mut);
	}
	sync_printf(
		ANSI_COLOR_CYAN
		"============================================\n\n" ANSI_COLOR_RESET);
}