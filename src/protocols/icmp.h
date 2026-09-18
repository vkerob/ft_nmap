#ifndef ICMP_H
#define ICMP_H

#include "request.h"
#include "scan.h"
#include "shared.h"
#include "typesdef.h"

#include <netinet/ip_icmp.h>

void handle_icmp_response(t_probe_queue *sent_list, const u16 source_port,
						  const struct in_addr ip_src, t_icmp_hdr icmp_hdr,
						  const t_scan_type scan_type, const u8 protocol,
						  t_eth_hdr *eth_hdr);

#endif
