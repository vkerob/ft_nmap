
#include "protocols.h"
#include "tcp.h"

// static void	handle_tcp_probe_response(
// 	t_target *target, u8 flags, t_scan_type scan_type, t_port *port)
// {

// (void)target;
// 	switch (scan_type)
// 	{
// 		case SCAN_SYN:
// 			if (flags & (TH_RST | TH_ACK))
// 			{
// 				port->port_state = CLOSE;
// 			}
// 			else if (flags & (TH_SYN | TH_ACK))
// 			{
// 				port->port_state = OPEN;
// 				// TODO: need to close the conneciton with FIN here otherwise
// 				// we'll get spam from the target with the same response
// 			}
// 			break ;
// 		case SCAN_ACK:
// 			if (flags & (TH_RST | TH_ACK))
// 			{
// 				port->port_state = UNFILTERED;
// 			}
// 			else{
// 				port->port_state = UNKNOWN;
// 			}
// 			break ;
// 		case SCAN_FIN:
// 		case SCAN_NULL:
// 		case SCAN_XMAS:
// 			if (flags & (TH_RST | TH_ACK))
// 			{
// 				port->port_state = FILTERED;
// 			}
// 			else{
// 				port->port_state = UNKNOWN;
// 			}
// 			break ;
// 		default:
// 			break ;
// 	}

// }

void handle_tcp_protocol(t_target *target, t_tcp_hdr *tcp_hdr)
{
	// t_port		port;
	t_scan_type scan_type;

	(void)target;
	(void)scan_type;
	// (void)port;
	(void)target;
	scan_type = determine_tcp_scan_type(tcp_hdr->th_dport);
	// scan_type_to_str(scan_type);
}
