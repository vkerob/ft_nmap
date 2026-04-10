#ifndef SCAN_H
#define SCAN_H

#define HIGHEST_PORT_STATE 3

#include "args.h"
#include "defines.h"
#include "typesdef.h"

#include <net/if.h>
#include <netinet/in.h>
#include <pcap/pcap.h>
#include <stdbool.h>

typedef enum e_port_state
{
	CLOSE,
	FILTERED,
	UNFILTERED,
	OPEN_FILTERED,
	UNKNOWN,
	OPEN
} t_port_state;

typedef enum e_port_state_reason
{
	CONNECTION_RESET,
	UNREACHABLE,
	NO_RESPONSE
}	t_port_state_reason;

typedef struct s_port
{
	u16				port_number;
	t_port_state	port_state;
	/* Why the port is in that state, maximum 3 reasons
		Ex: For a SYN scan:
			- No response received (even after retransmissions)	filtered
			- ICMP unreachable error (type 3, code 1, 2, 3, 9, 10, or 13)	filtered
		So maximum 2 reasons for TCP, but if the user run a UDP scan too we can a have third reason (which will be the same as one of the two before
		but it will printed separately in the output)
			- Other ICMP unreachable errors (type 3, code 1, 2, 9, 10, or 13)
	*/
	char *reason_tcp[2];
	char *reason_udp;
} t_port;

typedef struct s_port_output
{
	char *reasons[MAX_REASONS_NUMBER];
	u16 port_number;
	t_port_state port_state;
}	t_port_output;

typedef struct s_port_list
{
	/* Store the index of the port inside port_map_rev array and port_final_state array or 0 if the port is not scanned */
	u16	   *port_map;
	/* Store the state of each port for each type of scan*/
	t_port *port_map_rev[MAX_NB_SCAN_TYPE];
	/* Store the final state and the reason we deduce it for each port for each protocol (TCP and UDP) because
	the "Not shown output" is separated between those two (even for the same state)*/
	t_port_output *port_final_state[MAX_PROTO_COUNT];
	/* For each protocol (TCP and UDP) number of port in each state except open: filtered, close, open|filtered, unfiltered */
	int state_count[HIGHEST_PORT_STATE];
} t_port_list;

typedef struct s_iface_info
{
	char		   name[IFNAMSIZ];
	struct in_addr ip_addr; // ip of the interface, used as source ip in packets
	struct ether_addr mac_addr;	   // not defined yet, mac of the interface.
	u8				  iface_index; // index of the interface
} t_iface_info;

typedef struct s_program_info
{
	struct timeval start;
} t_program_info;



typedef struct s_target
{
	char		  *input;
	struct in_addr addr;
	t_port_list	   port_list;
	t_iface_info  *iface_info;
} t_target;

typedef enum e_scan_type
{
	SCAN_SYN = 0,
	SCAN_NULL,
	SCAN_ACK,
	SCAN_FIN,
	SCAN_XMAS,
	SCAN_UDP,
	SCAN_UNKNOWN
} t_scan_type;

typedef struct s_port_range_scan_type
{
	t_scan_type scan_type;
	u16			min_port_range;
	u16			max_port_range;
} t_port_range_scan_type;

typedef struct s_ctx
{
	t_target	  *targets;
	size_t		   target_count;
	t_iface_info  *ifaces;
	size_t		   iface_count;
	t_args		   args;
	t_program_info program_info;
	pcap_t		 **handles;
} t_ctx;

bool init_portlist(t_port_list *port_list, const u16 port_count,
				   u16 ports[MAX_PORT_COUNT], u8 scan_types[MAX_NB_SCAN_TYPE],
				   const u8 nb_scan_type, bool tcp_scan, bool udp_scan);

bool link_port_list_to_each_target(t_ctx *ctx);

void scan_type_to_str(t_scan_type scan_type, char buf[16]);

bool get_iface_info(t_iface_info **ifaces, size_t *iface_count,
					t_target *targets, size_t target_count);

void print_scan_results(t_ctx *ctx);

void set_port_state_reason(t_port *port, t_port_state_reason reason, u8 protocol);
#endif
