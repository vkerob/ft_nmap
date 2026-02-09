#include "ip.h"

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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
