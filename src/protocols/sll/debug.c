#include "sll.h"
#include "defines.h"

#include <stdio.h>

void	print_debug_sll_header(t_sll_hdr *sll_hdr)
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
