
#include "probe_request.h"
#include "scan.h"

#include <stdio.h>

void print_debug_probe_request(t_probe_request *request)
{
	printf(ANSI_COLOR_CYAN
		   "============================================\n" ANSI_COLOR_RESET);
	printf(ANSI_BOLD ANSI_COLOR_CYAN "New Probe Request:\n" ANSI_COLOR_RESET);
	printf(ANSI_COLOR_GREEN
		   "--------------------------------------------\n" ANSI_COLOR_RESET);
	printf(ANSI_COLOR_GREEN "  • Target: %s:%u\n" ANSI_COLOR_RESET,
		   request->target.ip, request->target.port);
	scan_type_to_str(request->type);
	printf(ANSI_COLOR_GREEN "  • ID: %u\n" ANSI_COLOR_RESET, request->id);
	printf(ANSI_COLOR_GREEN "  • Retries: %u\n" ANSI_COLOR_RESET,
		   request->retries);
	printf(ANSI_COLOR_GREEN "  • Status: %u\n" ANSI_COLOR_RESET,
		   request->status);
	printf(ANSI_COLOR_GREEN "  • Interface: %s\n" ANSI_COLOR_RESET,
		   request->iface_info.name);
	printf(ANSI_COLOR_GREEN "  • IP src Address: %s\n" ANSI_COLOR_RESET,
		   inet_ntoa(request->iface_info.ip_addr));
	printf(ANSI_COLOR_GREEN "  • iface index: %u\n" ANSI_COLOR_RESET,
		   request->iface_info.iface_index);
	printf(ANSI_COLOR_CYAN
		   "============================================\n" ANSI_COLOR_RESET);
}
