#ifndef PARSING_H
#define PARSING_H

#include "typesdef.h"
#include "scan.h"
#include "args.h"

#include <stdbool.h>

enum e_flags
{
	F_HELP = 1u << 0,
	F_IP_MODE = 1u << 1,
	F_FILE_MODE = 1u << 2,
	F_PORTS = 1u << 3,
	F_SCAN_TYPE = 1u << 4,
	F_SPEED = 1u << 5,
	F_SPOOF = 1u << 6
};

bool				parse_args(int argc, char **argv, t_args *args, char ***targets_input,
							size_t *target_count);
bool				get_targets_input(const char *arg, size_t *args_count, char ***targets,
							int mode, u8 flags);
bool				resolve_targets(char **inputs, size_t count, t_target **out);
void				free_targets(t_target **pt, size_t count);

#endif
