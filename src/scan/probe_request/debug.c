
#include "probe_request.h"

#include <stdio.h>

void	print_debug_probe_request(t_probe_request *request)
{

	printf(ANSI_COLOR_CYAN
		   "============================================\n" ANSI_COLOR_RESET);
	printf(ANSI_BOLD ANSI_COLOR_CYAN "New Probe Request:\n" ANSI_COLOR_RESET);
	printf(ANSI_COLOR_GREEN
		   "--------------------------------------------\n" ANSI_COLOR_RESET);
	printf(ANSI_COLOR_GREEN "  • Target: %s:%u\n" ANSI_COLOR_RESET,
		   request->target.ip, request->target.port);
	printf(ANSI_COLOR_GREEN "  • Type: %d\n" ANSI_COLOR_RESET, request->type);
	printf(ANSI_COLOR_GREEN "  • ID: %u\n" ANSI_COLOR_RESET, request->id);
	printf(ANSI_COLOR_CYAN
		   "============================================\n" ANSI_COLOR_RESET);
}
