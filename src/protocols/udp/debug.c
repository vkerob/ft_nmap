#include "udp.h"
#include "defines.h"

#include <stdio.h>

void	print_debug_udp_header(t_udp_hdr *udp_hdr)
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
