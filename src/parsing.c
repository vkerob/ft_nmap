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

static void free_tab(void **tab, size_t n)
{
	if (!tab)
		return;
	for (size_t i = 0; i < n; i++)
		free(tab[i]);
	free(tab);
}

void free_tabp(void ***ptab, size_t n)
{
	if (!ptab || !*ptab)
		return;
	free_tab(*ptab, n);
	*ptab = NULL;
}

// if we don't need the numeric IP strings, we can remove targets_ip
// parameter later
bool resolve_hosts(char **hosts, size_t host_count,
				   struct sockaddr_in **targets_addr, char ***targets_ip)
{
	*targets_addr = malloc(sizeof(struct sockaddr_in) * host_count);
	if (*targets_addr == NULL)
		return false;

	*targets_ip = malloc(sizeof(char *) * host_count);
	if (*targets_ip == NULL)
	{
		free(*targets_addr);
		*targets_addr = NULL;
		return false;
	}

	for (size_t i = 0; i < host_count; i++)
	{
		(*targets_ip)[i] = malloc(INET_ADDRSTRLEN);
		if ((*targets_ip)[i] == NULL)
		{
			free_tabp((void ***)(targets_ip), i);
			free(*targets_addr);
			*targets_addr = NULL;
			return false;
		}

		if (resolve_host(hosts[i], &(*targets_addr)[i], (*targets_ip)[i]) == false)
		{
			free_tabp((void ***)(targets_ip), i + 1);
			free(*targets_addr);
			*targets_addr = NULL;
			return false;
		}
	}
	return true;
}

// Resolve hostname/IP to IPv4 sockaddr and numeric string; no reverse DNS
bool resolve_host(const char *host, struct sockaddr_in *dst,
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
