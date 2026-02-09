#include "icmp.h"
#include "tcp.h"
#include "scan.h"
#include "protocols.h"

/* Can either be UDP or TCP protocol */
void	handle_icmp_protocol(t_target *target, t_datalink_hdr *datalink_hdr, u8 proto)
{
	t_port			port;
	t_scan_type	scan_type;

	if (proto == IPPROTO_TCP)
	{
		scan_type = determine_tcp_scan_type(datalink_hdr->tcp_hdr.th_sport);
	}
	else{
		scan_type = SCAN_UDP;

	}
	if (scan_type != SCAN_UNKNOWN)
	{
		if (find_port_object(target, &datalink_hdr->tcp_hdr, scan_type, &port))
		{
			// handle_probe_response(target, datalink_hdr->tcp_hdr.th_flags, scan_type, &port);
		}
	}
}
