#ifndef SCAN_H
#define SCAN_H

#include "args.h"
#include "defines.h"
#include "typesdef.h"

#include <net/if.h>
#include <netinet/in.h>
#include <pcap/pcap.h>
#include <stdbool.h>

typedef enum e_port_state
{
	DEFAULT,
	CLOSE,
	FILTERED,
	UNFILTERED,
	OPEN_FILTERED,
	OPEN,
	UNKNOWN
} t_port_state;

typedef enum e_port_state_reason
{
	CONNECTION_RESET,
	UNREACHABLE,
	NO_RESPONSE,
	SYN_ACK
} t_port_state_reason;

typedef struct s_port
{
	u16			 port_number;
	t_port_state port_state;
	char		*reasons[MAX_REASONS_NUMBER];
} t_port;

typedef struct s_port_output
{
	char		*reasons[MAX_REASONS_NUMBER];
	u16			 port_number;
	t_port_state port_state;
	char		 version[128]; // banner grabbed via version detection
} t_port_output;

typedef struct s_port_state_and_reason
{
	int			 count;
	char		*reason;
	t_port_state port_state;

	/* Maximum of 2 reasons, only be filled with tcp scans if more than one
	reason for a port state exist to know the subcount of each */
	struct s_port_state_and_reason *first_reason;
	struct s_port_state_and_reason *second_reason;

	// NULL if child node
	struct s_port_state_and_reason *next;

} t_port_state_and_reason;

typedef struct s_port_list
{
	/* Store the index of the port inside port_map_rev array and
	 * port_final_state array or 0 if the port is not scanned */
	int *port_map;

	/* Store the state of each port for each type of scan,
		So if all scans types are run, this will store 6 differents state for a
	   same port (5 for TCP and 1 for UDP)*/
	t_port *port_map_rev[MAX_NB_SCAN_TYPE];

	/* Store the final state and the reason we deduce it for each port for each
	protocol (TCP and UDP) because the "Not shown output" is separated between
	those two (even for the same state)*/
	t_port_output *port_final_state[MAX_PROTO_COUNT];

	/* For each protocol (TCP and UDP) number of port in each state with their
	respective reason and occurences, this list is not sorted in any way */
	t_port_state_and_reason *state_and_reason[MAX_PROTO_COUNT];

	int state_count[HIGHEST_PORT_STATE];
} t_port_list;

typedef struct s_iface_info
{
	char		   name[IFNAMSIZ];
	struct in_addr ip_addr; // ip of the interface, used as source ip in packets
	u8				  iface_index; // index of the interface
} t_iface_info;

typedef struct s_program_info
{
	struct timeval start;
} t_program_info;

typedef struct s_target
{
	char		  *input;
	char		  *hostname; // reverse DNS result (NULL if not found or same as input)
	struct in_addr addr;
	t_port_list	   port_list;
	t_iface_info  *iface_info;
	u8			   os_ttl;        // TTL from first SYN-ACK received (0 = not captured)
	u16			   os_tcp_window; // TCP window from first SYN-ACK received
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


typedef struct s_port_svc {
	u16 port;
	char *name;
}	t_port_svc;

typedef struct s_ctx
{
	t_target	  *targets;
	size_t		   target_count;
	t_iface_info  *ifaces;
	size_t		   iface_count;
	t_args		   args;
	t_port_svc *port_svc[MAX_PROTO_COUNT];
	t_program_info program_info;
} t_ctx;

bool init_portlist(t_port_list *port_list, u16 port_count,
				   u16 ports[MAX_PORT_COUNT], u8 scan_types[MAX_NB_SCAN_TYPE],
				   u8 nb_scan_type, bool tcp_scan, bool udp_scan, u16 *max_port_nb);

bool init_port_lists(t_ctx *ctx);

void scan_type_to_str(t_scan_type scan_type, char buf[16]);

bool get_iface_info(t_iface_info **ifaces, size_t *iface_count,
					t_target *targets, size_t target_count);

void print_scan_results(t_ctx *ctx);

void set_port_state_reason(t_port *port, t_port_state_reason reason);

void grab_versions(t_target *target, t_args *args);

const char *guess_os(u8 ttl, u16 tcp_window);

bool resolve_services_name(u16 port_count, int *port_map,
								 t_port_svc *(*arr)[MAX_PROTO_COUNT], bool udp_scan, bool tcp_scan);

void free_services(t_port_svc *(*head)[MAX_PROTO_COUNT], u16 port_count);

#endif
