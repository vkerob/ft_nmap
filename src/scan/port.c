#include "scan.h"

void	create_port(u16 port_number, u8 proto, t_port *port)
{
	port->port_number = port_number;
	port->proto = proto;
}
