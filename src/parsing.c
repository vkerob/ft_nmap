#include "parsing.h"
#include "ft_nmap.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

void free_tabp(void ***ptab, size_t count)
{
	if (!ptab || !*ptab)
		return;
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

static char *trim_inplace(char *str)
{
	if (!str)
		return NULL;

	while (*str && isspace((unsigned char)*str))
		str++;

	size_t len = strlen(str);
	while (len > 0 && isspace((unsigned char)str[len - 1]))
		str[--len] = '\0';

	return str;
}

static bool parse_port_strict(const char *s, uint16_t *out)
{
	if (!s || !*s)
		return false;

	errno = 0;
	char		 *end = NULL;
	unsigned long value = strtoul(s, &end, 10);

	if (errno != 0)
		return false; // overflow/underflow
	if (end == s)
		return false; // no digits parsed
	if (*end != '\0')
		return false; // extra characters after number

	if (value < MIN_PORT_NUMBER || value > MAX_PORT_NUMBER)
		return false;

	*out = (uint16_t)value;
	return true;
}

static bool contains_port(const uint16_t *ports, size_t count, uint16_t port)
{
	for (size_t i = 0; i < count; i++)
		if (ports[i] == port)
			return true;
	return false;
}

static bool push_port(uint16_t *ports, size_t *count, uint16_t port)
{
	if (contains_port(ports, *count, port))
		return true;

	if (*count >= MAX_PORTS_COUNT)
		return false;

	ports[*count] = port;
	(*count)++;
	return true;
}

static bool parse_token_and_push(char *token, uint16_t *ports, size_t *count)
{
	char *dash = strchr(token, '-');

	if (!dash)
	{
		uint16_t port;
		if (!parse_port_strict(token, &port))
		{
			fprintf(stderr, "ft_nmap: invalid port: '%s'\n", token);
			return false;
		}
		if (!push_port(ports, count, port))
		{
			fprintf(stderr, "ft_nmap: too many ports (max %d)\n",
					MAX_PORTS_COUNT);
			return false;
		}
		return true;
	}

	if (strchr(dash + 1, '-') != NULL)
	{
		fprintf(stderr, "ft_nmap: invalid port range: '%s'\n", token);
		return false;
	}

	*dash = '\0';
	char *left = token;
	char *right = dash + 1;

	if (*left == '\0' || *right == '\0')
	{
		fprintf(stderr, "ft_nmap: invalid port range: '%s-%s'\n", left, right);
		return false;
	}

	uint16_t port_left, port_right;
	if (!parse_port_strict(left, &port_left)
		|| !parse_port_strict(right, &port_right) || port_left > port_right)
	{
		fprintf(stderr, "ft_nmap: invalid port range: '%s-%s'\n", left, right);
		return false;
	}

	for (uint32_t port = port_left; port <= port_right; port++)
	{
		if (!push_port(ports, count, (uint16_t)port))
		{
			fprintf(stderr, "ft_nmap: too many ports (max %d)\n",
					MAX_PORTS_COUNT);
			return false;
		}
	}

	return true;
}

ssize_t parse_ports(const char *port_str, uint16_t *ports)
{
	char *copy = strdup(port_str);
	if (!copy)
		return -1;

	size_t count = 0;
	bool   ok = true;

	char *tok = strtok(copy, ",");
	while (tok != NULL)
	{
		char *trim_str = trim_inplace(tok);

		if (!trim_str || *trim_str == '\0')
		{
			fprintf(stderr, "ft_nmap: invalid empty port token in: '%s'\n",
					port_str);
			ok = false;
			break;
		}

		if (!parse_token_and_push(trim_str, ports, &count))
		{
			ok = false;
			break;
		}

		tok = strtok(NULL, ",");
	}

	free(copy);
	if (!ok)
		return -1;
	return (ssize_t)count;
}

bool parse_args(int argc, char **argv, t_args *args, char ***targets_input)
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
			*targets_input
				= get_targets_input(optarg, &args->target_count, IP_MODE);
			if (*targets_input == NULL)
				return true;
			break;
		case FILE_MODE:
			SET(args->flags, F_FILE_MODE);
			*targets_input
				= get_targets_input(optarg, &args->target_count, FILE_MODE);
			if (*targets_input == NULL)
				return true;
			break;
		case PORTS:
			SET(args->flags, F_PORTS);
			ssize_t port_count = parse_ports(optarg, args->ports);
			if (port_count == -1)
				return true;
			args->port_count = port_count;
			break;
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
	if (optind < argc)
	{
		fprintf(stderr, "ft_nmap: unexpected argument: %s\n", argv[optind]);
		return true;
	}
	if (!HAS(args->flags, F_PORTS))
	{
		// fill 1..1024
		args->port_count = 1024;
		for (size_t i = 0; i < 1024; i++)
			args->ports[i] = (uint16_t)(i + 1);
	}

	return false;
}
