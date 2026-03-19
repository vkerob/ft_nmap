#ifndef ICMP_H
#define ICMP_H

#include "request.h"
#include "shared.h"
#include "typesdef.h"
#include "scan.h"

#include <netinet/ip_icmp.h>

void handle_icmp_response(t_probe_queue *sent_list, u16 source_port, struct in_addr ip_src,
	u8 code, t_scan_type scan_type);

#endif
