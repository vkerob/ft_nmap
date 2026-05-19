#include "debug.h"
#include "defines.h"
#include "ip.h"
#include "scan.h"
#include "udp.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
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

bool print_debug_packet_send(t_probe *probe, struct timeval *relative_sent_time,
							 t_datalink_hdr *datalink_hdr, t_ip *ip_hdr)
{

	char src[32];
	char target[32];

	static int domain = AF_INET;
	if (inet_ntop(domain, (const void *)&probe->target->addr, target,
				  sizeof(src))
		== NULL)
	{
		LOG("ft_nmap: inet_pton: %s\n", strerror(errno));
		return true;
	}
	if (inet_ntop(domain, (const void *)&probe->target->iface_info->ip_addr,
				  src, sizeof(target))
		== NULL)
	{
		LOG("ft_nmap: inet_pton: %s\n", strerror(errno));
		return true;
	}

	pthread_mutex_lock(&printf_mutex);
	printf("SENT (%ld.%06lu) %s %s:%d > %s:%d ", relative_sent_time->tv_sec,
		   (unsigned long)relative_sent_time->tv_usec,
		   probe->type == SCAN_UDP ? "UDP" : "TCP", src,
		   ntohs(datalink_hdr->tcp_hdr.th_sport), target,
		   ntohs(datalink_hdr->tcp_hdr.th_dport));

	printf("ttl: %d ", ip_hdr->ip_ttl);
	printf("id: %d ", ntohs(ip_hdr->ip_id));
	printf("iplen: %d ", ntohs(ip_hdr->ip_len));
	if (probe->type != SCAN_UDP)
	{
		if (datalink_hdr->tcp_hdr.th_flags & TH_URG)
			printf("URG ");
		if (datalink_hdr->tcp_hdr.th_flags & TH_ACK)
			printf("ACK ");
		if (datalink_hdr->tcp_hdr.th_flags & TH_PUSH)
			printf("PUSH ");
		if (datalink_hdr->tcp_hdr.th_flags & TH_RST)
			printf("RST ");
		if (datalink_hdr->tcp_hdr.th_flags & TH_SYN)
			printf("SYN ");
		if (datalink_hdr->tcp_hdr.th_flags & TH_FIN)
			printf("FIN ");
		printf("seq: %u ", ntohl(datalink_hdr->tcp_hdr.th_seq));
		printf("win: %d ", ntohs(datalink_hdr->tcp_hdr.th_win));
		printf("cksum: 0x%04x" ANSI_COLOR_RESET,
			   ntohs(datalink_hdr->tcp_hdr.th_sum));
	}
	printf("\n");
	pthread_mutex_unlock(&printf_mutex);
	return false;
}

bool print_debug_packet_recv(const struct ip	  *ip_hdr,
							 const t_datalink_hdr *datalink_hdr,
							 const t_datalink_hdr *nested_datalink_hdr,
							 const struct ip	  *nested_ip_hdr,
							 const struct timeval *relative_recv_time)
{
	char	   src[32];
	char	   dst[32];
	static int domain = AF_INET;

	if (inet_ntop(domain, (const void *)&ip_hdr->ip_src, src, sizeof(src))
		== NULL)
	{
		LOG("ft_nmap: inet_pton: %s\n", strerror(errno));
		return true;
	}
	if (inet_ntop(domain, (const void *)&ip_hdr->ip_dst, dst, sizeof(dst))
		== NULL)
	{
		LOG("ft_nmap: inet_pton: %s\n", strerror(errno));
		return true;
	}

	pthread_mutex_lock(&printf_mutex);
	printf("RCVD (%ld.%06lu) ", relative_recv_time->tv_sec,
		   (unsigned long)relative_recv_time->tv_usec);

	if (ip_hdr->ip_p == IPPROTO_TCP)
	{
		printf("TCP %s:%d > %s:%d ", src, ntohs(datalink_hdr->tcp_hdr.th_sport),
			   dst, ntohs(datalink_hdr->tcp_hdr.th_dport));
		if (datalink_hdr->tcp_hdr.th_flags & TH_URG)
			printf("URG ");
		if (datalink_hdr->tcp_hdr.th_flags & TH_ACK)
			printf("ACK ");
		if (datalink_hdr->tcp_hdr.th_flags & TH_PUSH)
			printf("PUSH ");
		if (datalink_hdr->tcp_hdr.th_flags & TH_RST)
			printf("RST ");
		if (datalink_hdr->tcp_hdr.th_flags & TH_SYN)
			printf("SYN ");
		if (datalink_hdr->tcp_hdr.th_flags & TH_FIN)
			printf("FIN ");
		if (datalink_hdr->tcp_hdr.th_flags & 0x00)
			printf(". ");
		printf("ttl: %d ", ip_hdr->ip_ttl);
		printf("id: %d ", ntohs(ip_hdr->ip_id));
		printf("iplen: %d ", ntohs(ip_hdr->ip_len));
		printf("seq: %u ", ntohl(datalink_hdr->tcp_hdr.th_seq));
		printf("win: %d ", ntohs(datalink_hdr->tcp_hdr.th_win));
		printf("cksum: 0x%04x " ANSI_COLOR_RESET,
			   ntohs(datalink_hdr->tcp_hdr.th_sum));
	}
	if (ip_hdr->ip_p == IPPROTO_UDP)
	{
		printf("UDP %s:%d > %s:%d ", src, ntohs(datalink_hdr->udp_hdr.uh_sport),
			   dst, ntohs(datalink_hdr->udp_hdr.uh_dport));
		printf("ttl: %d ", ntohs(ip_hdr->ip_ttl));
		printf("id: %d ", ntohs(ip_hdr->ip_id));
		printf("iplen: %d ", ntohs(ip_hdr->ip_len));
	}
	if (ip_hdr->ip_p == IPPROTO_ICMP)
	{
		u16 source_port = 0;
		u16 dest_port = 0;

		if (nested_ip_hdr->ip_p == IPPROTO_UDP)
		{
			source_port = ntohs(nested_datalink_hdr->udp_hdr.uh_sport);
			dest_port = ntohs(nested_datalink_hdr->udp_hdr.uh_dport);
		}
		else if (nested_ip_hdr->ip_p == IPPROTO_TCP)
		{
			source_port = ntohs(nested_datalink_hdr->tcp_hdr.th_sport);
			dest_port = ntohs(nested_datalink_hdr->tcp_hdr.th_dport);
		}

		printf("ICMP [%s:%d > %s:%d (type=%d/code=%d) ] IP [ ttl=%d id=%d "
			   "iplen=%d ]",
			   src, dest_port, dst, source_port,
			   ICMP_TYPE(datalink_hdr->icmp_hdr),
			   ICMP_CODE(datalink_hdr->icmp_hdr), ip_hdr->ip_ttl,
			   ntohs(ip_hdr->ip_id), ntohs(ip_hdr->ip_len));
	}
	printf("\n");
	pthread_mutex_unlock(&printf_mutex);
	return false;
}

void print_debug_max_retries_exceeded(const t_probe *probe)
{
	pthread_mutex_lock(&printf_mutex);
	printf(ANSI_COLOR_CYAN
		   "============================================\n" ANSI_COLOR_RESET);
	printf(ANSI_BOLD ANSI_COLOR_YELLOW
		   "Probe %u exceed the retries: %d\n" ANSI_COLOR_RESET,
		   probe->id, probe->retries);
	printf(ANSI_COLOR_CYAN "============================================"
						   "\n\n" ANSI_COLOR_RESET);
	pthread_mutex_unlock(&printf_mutex);
}

void print_debug_probe_exceed_timeout(const t_probe		   *probe,
									  const struct timeval *current_time,
									  const unsigned long	seconds_elapsed)
{
	pthread_mutex_lock(&printf_mutex);
	printf(ANSI_COLOR_CYAN
		   "============================================\n" ANSI_COLOR_RESET);
	printf(ANSI_BOLD ANSI_COLOR_YELLOW "Probe %u timed out:\n" ANSI_COLOR_RESET,
		   probe->id);

	printf(ANSI_COLOR_YELLOW "  • Sent at: %ld.%06u\n" ANSI_COLOR_RESET,
		   probe->timestamp.tv_sec, (unsigned int)probe->timestamp.tv_usec);
	printf(ANSI_COLOR_YELLOW "  • Current time: %ld.%06u\n" ANSI_COLOR_RESET,
		   current_time->tv_sec, (unsigned int)current_time->tv_usec);
	printf(ANSI_COLOR_YELLOW "  • Elapsed time: %ld \n" ANSI_COLOR_RESET,
		   seconds_elapsed);
	printf(ANSI_COLOR_YELLOW "  • Number of retries: %d\n" ANSI_COLOR_RESET,
		   probe->retries);
	printf(ANSI_COLOR_CYAN "============================================"
						   "\n\n" ANSI_COLOR_RESET);
	pthread_mutex_unlock(&printf_mutex);
}

void print_debug_sent_queue_state(const u8			   iface_index,
								  const t_probe_queue *sent)
{
	pthread_mutex_lock(&printf_mutex);
	printf(ANSI_COLOR_CYAN
		   "============================================\n" ANSI_COLOR_RESET);
	printf(ANSI_BOLD ANSI_COLOR_YELLOW
		   "SENT QUEUE %d INTERFACE:\n" ANSI_COLOR_RESET,
		   iface_index);
	printf(ANSI_COLOR_CYAN
		   "============================================\n\n" ANSI_COLOR_RESET);
	printf(ANSI_COLOR_YELLOW "Number of probe request: %d\n" ANSI_COLOR_RESET,
		   sent->nb_probe);
	printf(ANSI_COLOR_CYAN "============================================"
						   "\n\n" ANSI_COLOR_RESET);
	pthread_mutex_unlock(&printf_mutex);
}

void print_debug_thread_startup(pthread_t phid, const char *func_name)
{
	pthread_mutex_lock(&printf_mutex);
	printf(ANSI_COLOR_CYAN
		   "============================================\n" ANSI_COLOR_RESET);
	printf(ANSI_BOLD ANSI_COLOR_RED "THREAD STATE\n" ANSI_COLOR_RESET);
	printf(ANSI_COLOR_CYAN
		   "============================================\n\n" ANSI_COLOR_RESET);
	printf(ANSI_COLOR_RED "Thread %lu enter %s()\n" ANSI_COLOR_RESET,
		   (unsigned long)phid, (char *)func_name);
	pthread_mutex_unlock(&printf_mutex);
}

void print_debug_thread_leave(pthread_t phid, const char *func_name)
{
	pthread_mutex_lock(&printf_mutex);
	printf(ANSI_COLOR_CYAN
		   "============================================\n" ANSI_COLOR_RESET);
	printf(ANSI_BOLD ANSI_COLOR_RED "THREAD STATE\n" ANSI_COLOR_RESET);
	printf(ANSI_COLOR_CYAN
		   "============================================\n\n" ANSI_COLOR_RESET);
	printf(ANSI_COLOR_RED "Thread %lu leave %s()\n" ANSI_COLOR_RESET,
		   (unsigned long)phid, func_name);
	printf(ANSI_COLOR_CYAN "============================================"
						   "\n\n" ANSI_COLOR_RESET);
	pthread_mutex_unlock(&printf_mutex);
}

void print_debug_concise_probe(const t_probe *probe)
{
	pthread_mutex_lock(&printf_mutex);
	printf(ANSI_COLOR_CYAN "==========================================="
						   "==\n" ANSI_COLOR_RESET);
	printf("Probe Destination Port: %hu\n", probe->port);
	printf("Probe Target IP Value: %u\n", probe->target->addr.s_addr);
	char buf[16];
	scan_type_to_str(probe->type, buf);
	printf("Probe Scan Type: %s\n", buf);
	printf(ANSI_COLOR_CYAN "============================================"
						   "\n\n" ANSI_COLOR_RESET);
	pthread_mutex_unlock(&printf_mutex);
}

void print_debug_sender_thread_proceed_probe(pthread_t			   phid,
											 const t_probe		  *request,
											 const struct timeval *tv)
{
	pthread_mutex_lock(&printf_mutex);
	printf(ANSI_COLOR_CYAN
		   "============================================\n" ANSI_COLOR_RESET);
	printf(ANSI_BOLD ANSI_COLOR_RED "THREAD LOG\n" ANSI_COLOR_RESET);
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
	pthread_mutex_lock(&printf_mutex);
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

	pthread_mutex_unlock(&printf_mutex);
}

void print_debug_tcp_header(t_tcp_hdr *tcp_hdr)
{
	pthread_mutex_lock(&printf_mutex);
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
	pthread_mutex_unlock(&printf_mutex);
}

void print_debug_sll_protocol(const int protocol)
{
	pthread_mutex_lock(&printf_mutex);
	if (protocol != ETHERTYPE_IP)
	{
		printf(ANSI_COLOR_RED
			   "Captured non-IP packet: Protocol=0x%04x\n" ANSI_COLOR_RESET,
			   protocol);
	}
	pthread_mutex_unlock(&printf_mutex);
}

void print_debug_packet_start()
{
	pthread_mutex_lock(&printf_mutex);
	printf(ANSI_COLOR_CYAN
		   "============================================\n" ANSI_COLOR_RESET);
	printf(ANSI_BOLD ANSI_COLOR_CYAN "Start of Packet\n" ANSI_COLOR_RESET);
	printf(ANSI_COLOR_CYAN
		   "============================================\n" ANSI_COLOR_RESET);
	pthread_mutex_unlock(&printf_mutex);
}

void print_debug_packet_end()
{
	pthread_mutex_lock(&printf_mutex);
	printf(ANSI_COLOR_CYAN
		   "============================================\n" ANSI_COLOR_RESET);
	printf(ANSI_BOLD ANSI_COLOR_CYAN "End of Packet\n" ANSI_COLOR_RESET);
	printf(ANSI_COLOR_CYAN
		   "============================================\n\n" ANSI_COLOR_RESET);
	pthread_mutex_unlock(&printf_mutex);
}

void print_debug_ethernet_header(t_eth_hdr *eth_header)
{
	pthread_mutex_lock(&printf_mutex);
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
	pthread_mutex_unlock(&printf_mutex);
}

void print_debug_definitive_port_state_tcp(t_port_output *port)
{

	pthread_mutex_lock(&printf_mutex);
	printf(ANSI_BOLD ANSI_COLOR_CYAN "TCP Port %d: \n" ANSI_COLOR_RESET,
		   port->port_number);
	printf(ANSI_COLOR_CYAN "State: %s\n" ANSI_COLOR_RESET,
		   port_state_to_str(port->port_state));
	printf(ANSI_COLOR_CYAN "Reasons: \n" ANSI_COLOR_RESET);
	printf(ANSI_COLOR_CYAN "  • %s\n" ANSI_COLOR_RESET, port->reasons[0]);
	if (port->reasons[1] != NULL)
	{
		printf(ANSI_COLOR_CYAN "  • %s\n" ANSI_COLOR_RESET, port->reasons[1]);
	}
	pthread_mutex_unlock(&printf_mutex);
}

void print_debug_icmp_header(t_icmp_hdr *icmp_hdr)
{
	pthread_mutex_lock(&printf_mutex);
	printf(ANSI_BOLD ANSI_COLOR_CYAN "\nICMP Header:\n" ANSI_COLOR_RESET);
	printf(ANSI_COLOR_CYAN
		   "--------------------------------------------\n" ANSI_COLOR_RESET);
	printf(ANSI_COLOR_CYAN "  • Type: %d\n" ANSI_COLOR_RESET,
		   ICMP_TYPE(*icmp_hdr));
	printf(ANSI_COLOR_CYAN "  • Code: %d\n" ANSI_COLOR_RESET,
		   ICMP_CODE(*icmp_hdr));
	printf(ANSI_COLOR_CYAN "  • Checksum: 0x%04x\n" ANSI_COLOR_RESET,
		   ntohs(ICMP_CKSUM(*icmp_hdr)));
	pthread_mutex_unlock(&printf_mutex);
}

void print_debug_protocol(const int protocol)
{
	pthread_mutex_lock(&printf_mutex);
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
	pthread_mutex_unlock(&printf_mutex);
}

void print_debug_probe_request(const t_probe *request)
{
	char buf[16] = { 0 };

	pthread_mutex_lock(&printf_mutex);
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
	pthread_mutex_unlock(&printf_mutex);
}

void print_debug_ethernet_type(const int ether_type)
{
	pthread_mutex_lock(&printf_mutex);
	if (ether_type != ETHERTYPE_IP)
	{
		printf(ANSI_COLOR_RED
			   "Captured non-IP packet: EtherType=0x%04x\n" ANSI_COLOR_RESET,
			   ether_type);
	}
	pthread_mutex_unlock(&printf_mutex);
}

void print_debug_ip_header(struct ip *ip_hdr)
{
	pthread_mutex_lock(&printf_mutex);
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
	pthread_mutex_unlock(&printf_mutex);
}

void print_debug_datalink_type(const int datalink_type)
{
	pthread_mutex_lock(&printf_mutex);
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
	pthread_mutex_unlock(&printf_mutex);
}

void print_debug_parsing_args(const t_ctx ctx)
{
	pthread_mutex_lock(&printf_mutex);
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
	pthread_mutex_unlock(&printf_mutex);
}

void print_debug_iface_info(t_iface_info *ifaces, const size_t iface_count)
{
	pthread_mutex_lock(&printf_mutex);
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
	pthread_mutex_unlock(&printf_mutex);
}

void print_debug_receiver_data(const t_receiver_data *receiver_data)
{
	pthread_mutex_lock(&printf_mutex);
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
	pthread_mutex_unlock(&printf_mutex);
}

void print_debug_shared_data_probe(t_shared_data_sender *shared_data_probe,
								   t_iface_info			*ifaces)
{
	pthread_mutex_lock(&printf_mutex);
	printf(ANSI_COLOR_CYAN
		   "============================================\n" ANSI_COLOR_RESET);
	printf(ANSI_BOLD ANSI_COLOR_CYAN " SHARED DATA PROBE \n" ANSI_COLOR_RESET);
	printf(ANSI_COLOR_CYAN
		   "============================================\n" ANSI_COLOR_RESET);
	printf(ANSI_BOLD ANSI_COLOR_MAGENTA
		   "Number of interface: \n" ANSI_COLOR_RESET);
	printf(ANSI_COLOR_MAGENTA " • %zu\n" ANSI_COLOR_RESET,
		   shared_data_probe->iface_count);
	printf(ANSI_BOLD ANSI_COLOR_MAGENTA
		   "Number of ports to scan:\n" ANSI_COLOR_RESET);
	printf(ANSI_COLOR_MAGENTA " • %d\n" ANSI_COLOR_RESET,
		   shared_data_probe->port_count);
	printf(ANSI_COLOR_MAGENTA "Number of probe to send: \n" ANSI_COLOR_RESET);
	printf(ANSI_COLOR_MAGENTA " • %d\n" ANSI_COLOR_RESET,
		   shared_data_probe->to_send.nb_probe);
	printf(ANSI_BOLD ANSI_COLOR_MAGENTA
		   "Queue of probe to send:\n" ANSI_COLOR_RESET);
	printf(ANSI_COLOR_MAGENTA " • %p\n" ANSI_COLOR_RESET,
		   (void *)&shared_data_probe->to_send);
	printf(ANSI_BOLD ANSI_COLOR_MAGENTA
		   "\nQueues of sent probe (one per interface):\n" ANSI_COLOR_RESET);
	for (size_t i = 0; i < shared_data_probe->iface_count; i++)
	{
		printf(ANSI_COLOR_MAGENTA "	• Queue of %s interface\n" ANSI_COLOR_RESET,
			   ifaces[i].name);
		printf(ANSI_COLOR_MAGENTA "	• Queue address: %p\n" ANSI_COLOR_RESET,
			   (void *)&shared_data_probe->sent[i]);
		printf(ANSI_COLOR_MAGENTA "	• Queue mutex: %p\n" ANSI_COLOR_RESET,
			   (void *)&shared_data_probe->sent[i].mut);
	}
	printf(ANSI_COLOR_CYAN
		   "============================================\n\n" ANSI_COLOR_RESET);
	pthread_mutex_unlock(&printf_mutex);
}
