#include "args.h"
#include "defines.h"
#include "parsing.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

void free_targets(t_target **targets, size_t count)
{
	if (!targets || !*targets)
		return;
	for (size_t i = 0; i < count; i++)
		free((*targets)[i].input);
	free(*targets);
	*targets = NULL;
}

// Resolve hostname/IP to IPv4 sockaddr and numeric string; no reverse DNS
static bool resolve_target(const char *host, struct in_addr *dst)
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
	memcpy(dst, &((struct sockaddr_in *)res->ai_addr)->sin_addr, sizeof(*dst));

	freeaddrinfo(res);
	return true;
}

bool resolve_targets(char **inputs, size_t count, t_target **targets)
{
	t_target *tmp = calloc(count, sizeof(*tmp));
	if (!tmp)
	{
		fprintf(stderr, "ft_nmap: calloc failed: %s\n", strerror(errno));
		return true;
	}

	for (size_t i = 0; i < count; i++)
	{
		tmp[i].input = strdup(inputs[i]);
		if (!tmp[i].input)
		{
			fprintf(stderr, "ft_nmap: strdup failed: %s\n", strerror(errno));
			free_targets(&tmp, i);
			return true;
		}

		if (!resolve_target(inputs[i], &tmp[i].addr))
		{
			free_targets(&tmp, i + 1);
			return true;
		}
	}

	*targets = tmp;
	return false;
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

static bool parse_port_strict(const char *s, u16 *out)
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

	*out = (u16)value;
	return true;
}

static bool contains_port(const u16 *ports, size_t count, u16 port)
{
	for (size_t i = 0; i < count; i++)
		if (ports[i] == port)
			return true;
	return false;
}

static bool push_port(u16 *ports, u16 *count, u16 port)
{
	if (contains_port(ports, *count, port))
		return true;

	if (*count >= MAX_PORT_COUNT)
		return false;

	ports[*count] = port;
	(*count)++;
	return true;
}

static bool parse_token_and_push(char *token, u16 *ports, u16 *count)
{
	char *dash = strchr(token, '-');

	if (!dash)
	{
		u16 port;
		if (!parse_port_strict(token, &port))
		{
			fprintf(stderr, "ft_nmap: invalid port: '%s'\n", token);
			return false;
		}
		if (!push_port(ports, count, port))
		{
			fprintf(stderr, "ft_nmap: too many ports (max %d)\n",
					MAX_PORT_COUNT);
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

	u16 port_left, port_right;
	if (!parse_port_strict(left, &port_left)
		|| !parse_port_strict(right, &port_right) || port_left > port_right)
	{
		fprintf(stderr, "ft_nmap: invalid port range: '%s-%s'\n", left, right);
		return false;
	}

	for (u32 port = port_left; port <= port_right; port++)
	{
		if (!push_port(ports, count, (u16)port))
		{
			fprintf(stderr, "ft_nmap: too many ports (max %d)\n",
					MAX_PORT_COUNT);
			return false;
		}
	}

	return true;
}

bool parse_ports(const char *port_str, u16 *ports, u16 *port_count)
{
	*port_count = 0;

	char *copy = strdup(port_str);
	if (!copy)
		return true;

	bool error = false;

	char *tok = strtok(copy, ",");
	while (tok != NULL)
	{
		char *trim_str = trim_inplace(tok);

		if (!trim_str || *trim_str == '\0')
		{
			fprintf(stderr, "ft_nmap: invalid empty port token in: '%s'\n",
					port_str);
			error = true;
			break;
		}

		if (!parse_token_and_push(trim_str, ports, port_count))
		{
			error = true;
			break;
		}

		tok = strtok(NULL, ",");
	}

	free(copy);
	return error;
}

static bool parse_scan_type(char *scan_str, u8 *out)
{
	char upper_scan_str[strlen(scan_str) + 1];
	strcpy(upper_scan_str, scan_str);

	for (size_t i = 0; upper_scan_str[i]; i++)
		upper_scan_str[i] = (char)toupper((unsigned char)upper_scan_str[i]);

	if (strcmp(upper_scan_str, "SYN") == 0)
	{
		*out = SCAN_SYN;
		return true;
	}
	else if (strcmp(upper_scan_str, "NULL") == 0)
	{
		*out = SCAN_NULL;
		return true;
	}
	else if (strcmp(upper_scan_str, "ACK") == 0)
	{
		*out = SCAN_ACK;
		return true;
	}
	else if (strcmp(upper_scan_str, "FIN") == 0)
	{
		*out = SCAN_FIN;
		return true;
	}
	else if (strcmp(upper_scan_str, "XMAS") == 0)
	{
		*out = SCAN_XMAS;
		return true;
	}
	else if (strcmp(upper_scan_str, "UDP") == 0)
	{
		*out = SCAN_UDP;
		return true;
	}
	fprintf(stderr, "ft_nmap: invalid scan type: '%s'\n", scan_str);
	return false;
}

bool parse_scan_types(char *scan_str, u8 (*out)[6], u8 *nb_scan_types)
{
	char *saveptr = NULL;
	char *token = NULL;
	u8	  scan_type = 0;

	do
	{
		if (saveptr == NULL)
		{
			token = strtok_r(scan_str, ",", &saveptr);
			if (token == NULL && saveptr != NULL)
			{
				token = saveptr;
			}
		}
		else
		{
			token = strtok_r(saveptr, ",", &saveptr);
		}
		if (parse_scan_type(token, &scan_type))
		{
			(*out)[*nb_scan_types] = scan_type;
		}
		else
		{
			return true;
		}
		(*nb_scan_types)++;
	} while (saveptr != NULL);
	return false;
}

static bool parse_speed_strict(const char *str, u8 *out)
{
	while (isspace((unsigned char)*str))
		str++;

	if (*str == '\0' || *str == '-' || *str == '+')
	{
		fprintf(stderr, "ft_nmap: invalid speed value: '%s'\n", str);
		return true;
	}

	errno = 0;
	char		 *end = NULL;
	unsigned long value = strtoul(str, &end, 10);

	if (errno != 0 || end == str)
	{
		fprintf(stderr, "ft_nmap: invalid speed value: '%s'\n", str);
		return true;
	}

	while (isspace((unsigned char)*end))
		end++;

	if (*end != '\0')
	{
		fprintf(stderr, "ft_nmap: invalid characters in speed value: '%s'\n",
				str);
		return true;
	}

	if (value > SPEED_MAX)
	{
		fprintf(stderr, "ft_nmap: speed must be between %d and %d\n", SPEED_MIN,
				SPEED_MAX);
		return true;
	}

	*out = (u8)value;
	return false;
}

bool parse_args(int argc, char **argv, t_args *args, char ***targets_input,
				size_t *target_count)
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
		{ "speedup", required_argument, 0, SPEED },
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
			if (get_targets_input(optarg, target_count, targets_input, IP_MODE,
								  args->flags))
				return true;
			break;

		case FILE_MODE:
			SET(args->flags, F_FILE_MODE);
			if (get_targets_input(optarg, target_count, targets_input,
								  FILE_MODE, args->flags))
				return true;
			break;

		case PORTS:
			SET(args->flags, F_PORTS);
			if (parse_ports(optarg, args->ports, &args->port_count))
				return true;
			break;

		case SCAN:
			SET(args->flags, F_SCAN_TYPE);
			if (parse_scan_types(optarg, &args->scan_types,
								 &args->nb_scan_types))
				return true;
			break;

		case SPEED:
			SET(args->flags, F_SPEED);
			if (parse_speed_strict(optarg, &args->speed))
				return true;
			break;
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
		args->port_count = MAX_PORT_COUNT;
		for (u16 i = 0; i < args->port_count; i++)
		{
			args->ports[i] = i + 1;
		}
	}

	if (!HAS(args->flags, F_SCAN_TYPE))
	{
		args->nb_scan_types = MAX_NB_SCAN_TYPE;
		for (u8 i = 0; i < args->nb_scan_types; i++)
		{
			args->scan_types[i] = i;
		}
	}
	return false;
}
