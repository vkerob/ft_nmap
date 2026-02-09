#include "tcp.h"

#include <stdio.h>

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
	printf(ANSI_COLOR_GREEN"  • Flags: " );
	if (tcp_hdr->th_flags & TH_URG) printf("URG ");
	if (tcp_hdr->th_flags & TH_ACK) printf("ACK ");
	if (tcp_hdr->th_flags & TH_PUSH) printf("PUSH ");
	if (tcp_hdr->th_flags & TH_RST) printf("RST ");
	if (tcp_hdr->th_flags & TH_SYN) printf("SYN ");
	if (tcp_hdr->th_flags & TH_FIN) printf("FIN ");
	printf("\n" ANSI_COLOR_RESET);

	printf(ANSI_COLOR_GREEN "  • Window Size: %d\n" ANSI_COLOR_RESET,
		   ntohs(tcp_hdr->th_win));
	printf(ANSI_COLOR_GREEN "  • Checksum: 0x%04x\n" ANSI_COLOR_RESET,
		   ntohs(tcp_hdr->th_sum));
	printf(ANSI_COLOR_GREEN "  • Urgent Pointer: %d\n" ANSI_COLOR_RESET,
		   ntohs(tcp_hdr->th_urp));
}
