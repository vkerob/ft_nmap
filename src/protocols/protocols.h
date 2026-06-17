
#ifndef PROTOCOLS_H
#define PROTOCOLS_H

#include "typesdef.h"

#include "request.h"
#include "scan.h"
#include "tcp.h"
#include "udp.h"

#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>

typedef union u_datalink_hdr
{
	t_tcp_hdr  tcp_hdr;
	t_udp_hdr  udp_hdr;
	t_icmp_hdr icmp_hdr;
} t_datalink_hdr;

u16 calculate_checksum(const void *buffer, int len);

#endif
