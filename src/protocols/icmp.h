#ifndef ICMP_H
#define ICMP_H

#include "request.h"
#include "shared.h"
#include "typesdef.h"
#include "scan.h"

#include <netinet/ip_icmp.h>

void handle_icmp_response(t_probe_queue *sent_list, const u16 source_port, const struct in_addr ip_src,
	const u8 code, const t_scan_type scan_type, const u8 protocol);

#endif
