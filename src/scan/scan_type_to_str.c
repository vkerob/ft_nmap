#include "scan.h"

#include <string.h>

void scan_type_to_str(const t_scan_type scan_type, char buf[16])
{
	switch (scan_type)
	{
	case SCAN_SYN:
		strcpy(buf, "SYN");
		break;
	case SCAN_NULL:
		strcpy(buf, "NULL");
		break;
	case SCAN_ACK:
		strcpy(buf, "ACK");
		break;
	case SCAN_FIN:
		strcpy(buf, "FIN");
		break;
	case SCAN_UDP:
		strcpy(buf, "UDP");
		break;
	case SCAN_XMAS:
		strcpy(buf, "XMAS");
		break;
	default:
		break;
	}
}
