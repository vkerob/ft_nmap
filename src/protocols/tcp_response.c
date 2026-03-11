
#include "protocols.h"
#include "request.h"
#include "tcp.h"

static t_probe *get_our_response(t_probe_queue *sent_list, u16 source_port,
								 struct in_addr ip_src, t_scan_type scan_type)
{
	t_probe *tmp = sent_list->head;
	t_probe *prev = NULL;

	while (tmp)
	{
		// printf(
		// 	ANSI_COLOR_CYAN
		// 	"=============================================\n" ANSI_COLOR_RESET);
		// printf("Probe Destination Port: %hu\n", target->port);
		// printf("Probe Target IP Value: %u\n", target->target->addr.s_addr);
		// char buf[16];
		// scan_type_to_str(target->type, buf);
		// printf("Probe Scan Type: %s\n", buf);
		// printf("Probe Sent Timestamp: %ld.%06d\n", target->timestamp.tv_sec,
		// 	   target->timestamp.tv_usec);
		// printf(ANSI_COLOR_CYAN "============================================"
		// 					   "\n\n" ANSI_COLOR_RESET);

		// printf("port equal: %d\n", source_port == target->port);
		// printf("scan type equal: %d\n", scan_type == target->type);
		// printf("target equal: %d\n",

		if (source_port == tmp->port && scan_type == tmp->type
			&& ip_src.s_addr == tmp->target->addr.s_addr)
		{
			printf(ANSI_BOLD ANSI_COLOR_MAGENTA
				   "Found target\n" ANSI_COLOR_RESET);

			break;
		}
		prev = tmp;
		tmp = tmp->next;
	}
	if (tmp)
	{
		// print_debug_probe_request(probe_pending);
		erase_reference_to_node(&sent_list->head, prev, tmp->next);
	}
	else
	{
		// Ideally if our filter is precise enough we do not enter this
		// condition
		return NULL;
	}
}

void handle_tcp_response(t_probe_queue *sent_list, u8 flags,
						 t_scan_type scan_type, u16 source_port,
						 struct in_addr ip_src)
{

	t_probe *probe
		= get_our_response(sent_list, source_port, ip_src, scan_type);

	if (!probe)
	{
		printf(ANSI_COLOR_YELLOW "Received response does not match any pending "
								 "probe\n" ANSI_COLOR_RESET);
		return;
	}
	int idx = probe->target->port_list.port_map[scan_type][source_port];
	switch (scan_type)
	{
	case SCAN_SYN:
		if (flags & (TH_RST | TH_ACK))
		{

			probe->target->port_list.port_map_rev[scan_type][idx].port_state
				= CLOSE;
		}
		else if (flags & (TH_SYN | TH_ACK))
		{
			probe->target->port_list.port_map_rev[scan_type][idx].port_state
				= OPEN;
		}
		break;
	case SCAN_ACK:
		if (flags & (TH_RST | TH_ACK))
		{
			probe->target->port_list.port_map_rev[scan_type][idx].port_state
				= UNFILTERED;
		}
		else
		{
			probe->target->port_list.port_map_rev[scan_type][idx].port_state
				= UNKNOWN;
		}
		break;
	case SCAN_FIN:
	case SCAN_NULL:
	case SCAN_XMAS:
		if (flags & (TH_RST | TH_ACK))
		{
			probe->target->port_list.port_map_rev[scan_type][idx].port_state
				= CLOSE;
		}
		else
		{
			probe->target->port_list.port_map_rev[scan_type][idx].port_state
				= UNKNOWN;
		}
		break;
	default:
		break;
	}
}
