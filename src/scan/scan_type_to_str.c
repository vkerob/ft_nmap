#include "scan.h"

#include <stdio.h>

void	scan_type_to_str(enum e_scan_type scan_type)
{
	if (scan_type == SCAN_SYN)
		printf("SYN\n");
	else if (scan_type == SCAN_NULL)
		printf("NULL\n");
	else if (scan_type == SCAN_ACK)
		printf("ACK\n");
	else if (scan_type == SCAN_FIN)
		printf("XMAS\n");
	else if (scan_type == SCAN_UDP)
		printf("UDP\n");
	else
		printf("UNKNOWN\n");
}
