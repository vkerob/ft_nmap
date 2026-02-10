#include "typesdef.h"
#include "scan.h"

// #include <stdbool.h>

// bool	find_port_object(
// 	t_target *target, t_tcp_hdr *tcp_hdr, t_scan_type scan_type, t_port *port)
// {
// 	u16	index = target->port_list.port_map[scan_type][tcp_hdr->th_sport];

// 	// 0 = port not present in our list
// 	// i = index in port_map_rev
// 	if (index != 0)
// 	{
// 		*port = target->port_list.port_map_rev[scan_type][index];
// 		printf("port number %d\n", port->port_number);
// 		return true;
// 	}
// 	return false;
// }
