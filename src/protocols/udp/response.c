#include "udp.h"

#include "scan.h"

//TODO: replace tcp hdr by udp hdr when we have the right header file
void	handle_udp_protocol(t_target *target, t_udp_hdr *udp_hdr)
{
	// t_scan_type	scan_type = determine_scan_type(IPPROTO_UDP, udp_hdr->uh_sport);
	// (void)scan_type;
	(void)target;
	(void)udp_hdr;
}
