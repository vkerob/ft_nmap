#ifndef PARSING_H
#define PARSING_H

#include "args.h"
#include "scan.h"
#include "typesdef.h"

#include <stdbool.h>

enum e_flags
{
	F_HELP = 1u << 0,
	F_IP_MODE = 1u << 1,
	F_FILE_MODE = 1u << 2,
	F_PORTS = 1u << 3,
	F_SCAN_TYPE = 1u << 4,
	F_SPEED = 1u << 5,
	F_PACKET_TRACE = 1u << 6,
	F_REASON = 1u << 7
};

bool parse_args(int argc, char **argv, t_args *args, char ***targets_input,
				size_t *target_count);
bool get_targets_input(const char *arg, size_t *args_count, char ***targets,
					   int mode, u8 flags);
bool resolve_targets(char **inputs, size_t count, t_target **out);
bool parse_scan_types(char *scan_str, u8 (*out)[6], u8 *nb_scan_types,
					  bool *tcp_scan, bool *udp_scan);
bool parse_ports(const char *port_str, u16 *ports, u16 *port_count);
void free_targets(t_target **pt, size_t count);

#endif
