#include "parsing.h"
#include "ft_nmap.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <getopt.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void free_tabp(void ***ptab, size_t count)
{
	for (size_t i = 0; i < count; i++)
		free((*ptab)[i]);
	free(*ptab);
	*ptab = NULL;
}

void free_targets(t_target **targets, size_t count)
{
	for (size_t i = 0; i < count; i++)
		free((*targets)[i].input);
	free(*targets);
	*targets = NULL;
}

// Resolve hostname/IP to IPv4 sockaddr and numeric string; no reverse DNS
static bool resolve_target(const char *host, struct sockaddr_in *dst,
						   char ipbuf[INET_ADDRSTRLEN])
{
	struct addrinfo	 hints;
	struct addrinfo *res = NULL;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET; // IPv4 only (c.f. subject)
	int rc = getaddrinfo(host, NULL, &hints, &res);
	if (rc != 0)
	{
		fprintf(stderr, "Error: Invalid/unknown host '%s': %s\n", host,
				gai_strerror(rc));
		return false;
	}

	// Copy the first IPv4 result
	memset(dst, 0, sizeof(*dst));
	memcpy(dst, res->ai_addr, sizeof(*dst));

	freeaddrinfo(res);
	// Produce numeric IP string for display
	if (inet_ntop(AF_INET, &dst->sin_addr, ipbuf, INET_ADDRSTRLEN) == NULL)
	{
		perror("inet_ntop");
		return false;
	}

	return true;
}

bool resolve_targets(char **inputs, size_t count, t_target **targets)
{
	t_target *targets_tmp = calloc(count, sizeof(*targets_tmp));
	if (!targets_tmp)
		return false;

	for (size_t i = 0; i < count; i++)
	{
		targets_tmp[i].input = strdup(inputs[i]);
		if (!targets_tmp[i].input)
		{
			free_targets(&targets_tmp, i);
			return false;
		}

		if (!resolve_target(inputs[i], &targets_tmp[i].addr, targets_tmp[i].ip))
		{
			free_targets(&targets_tmp, i + 1);
			return false;
		}
	}
	*targets = targets_tmp;
	return true;
}

bool parse_args(int argc, char **argv, t_args *args)
{
	// short options (: argument required)
	const char *optstr = "";
	// long options
	const struct option long_options[] = {
		{ "help", no_argument, 0, HELP },
		{ "ip", required_argument, 0, IP_MODE },
		{ "file", required_argument, 0, FILE_MODE },
		{ "ports", required_argument, 0, PORTS },
		{ "scan", required_argument, 0, SCAN },
		{ "speed", required_argument, 0, SPEED },
		{ 0, 0, 0, 0 } // required terminator
	};
	opterr = 0; // we handle errors ourselves
	int flag;
	while ((flag = getopt_long(argc, argv, optstr, long_options, NULL)) != -1)
	{
		switch (flag)
		{
		case HELP:
			SET(args->flags, F_HELP);
			break;
		case IP_MODE:
			SET(args->flags, F_IP_MODE);
			args->targets_input
				= get_targets_input(optarg, &args->target_count, IP_MODE);
			if (args->targets_input == NULL)
				return true;
			break;
		case FILE_MODE:
			SET(args->flags, F_FILE_MODE);
			args->targets_input
				= get_targets_input(optarg, &args->target_count, FILE_MODE);
			if (args->targets_input == NULL)
				return true;
			break;
		// case PORTS:
		// 	SET(args->flags, F_PORTS);
		// 	if (parse_ports(optarg) != 0)
		// 		return true;
		// 	break;
		// case SCAN:
		// 	SET(args->flags, F_SCAN_TYPE);
		// 	if (parse_scan_type(optarg) != 0)
		// 		return true;
		// 	break;
		// case SPEED:
		// 	SET(args->flags, F_SPEED);
		// 	if (parse_speed(optarg) != 0)
		// 		return true;
		// 	break;
		case '?':
		case ':':
			fprintf(stderr, "ft_nmap: Invalid arguments. Use --help for usage "
							"information.\n");
			return true;
		default:
			break;
		}
	}

	return false;
}
