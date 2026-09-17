#include "args.h"
#include "defines.h"
#include "parsing.h"
#include "utils.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <netdb.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

static void free_port_state_and_reason(t_port_state_and_reason *head)
{
	t_port_state_and_reason *tmp = head;
	t_port_state_and_reason *next = NULL;

	while (tmp)
	{
		free(tmp->first_reason);
		free(tmp->second_reason);
		next = tmp->next;
		free(tmp);
		tmp = next;
	}
}

void free_targets(t_target **targets, size_t count, u8 nb_scan_types,
				  u8 *scan_types)
{
	if (!targets || !*targets)
	{
		return;
	}

	for (size_t i = 0; i < count; i++)
	{
		for (u8 j = 0; j < nb_scan_types; j++)
		{
			const t_scan_type scan_type = scan_types[j];
			free((*targets)[i].port_list.port_map_rev[scan_type]);
		}

		free_port_state_and_reason(
			(*targets)[i].port_list.state_and_reason[TCP_INDEX]);
		free_port_state_and_reason(
			(*targets)[i].port_list.state_and_reason[UDP_INDEX]);
		free((*targets)[i].port_list.port_final_state[TCP_INDEX]);
		free((*targets)[i].port_list.port_final_state[UDP_INDEX]);
		free((*targets)[i].hostname);
		pthread_mutex_destroy(&(*targets)[i].mutex);
	}
	free(*targets);
	*targets = NULL;
}

// Forward resolution: hostname/IP -> IPv4
static int resolve_target(const char *host, struct in_addr *dst)
{
	struct addrinfo	 hints;
	struct addrinfo *res = NULL;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET; // IPv4 only (c.f. subject)
	const int rc = getaddrinfo(host, NULL, &hints, &res);

	if (rc != 0)
	{
		LOG("Error: Invalid/unknown host '%s': %s\n", host, gai_strerror(rc));
		return FAILURE;
	}

	// Copy the first IPv4 result
	memcpy(dst, &((struct sockaddr_in *)res->ai_addr)->sin_addr,
		   sizeof(struct in_addr));

	freeaddrinfo(res);
	return SUCCESS;
}

// Reverse DNS: IPv4 -> hostname (returns heap-allocated string or NULL)
static char *reverse_dns(struct in_addr addr)
{
	struct sockaddr_in sa;
	char			   host[NI_MAXHOST];

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr = addr;

	if (getnameinfo((struct sockaddr *)&sa, sizeof(sa), host, sizeof(host),
					NULL, 0, NI_NAMEREQD)
		!= 0)
		return NULL;
	return strdup(host);
}

int resolve_targets(char **inputs, const size_t count, t_target **targets)
{
	*targets = calloc(count, sizeof(t_target));
	if (*targets == NULL)
	{
		LOG("ft_nmap: calloc failed: %s\n", strerror(errno));
		return FAILURE;
	}
	t_target *tmp = *targets;

	for (size_t i = 0; i < count; i++)
		pthread_mutex_init(&tmp[i].mutex, NULL);

	for (size_t i = 0; i < count; i++)
	{
		tmp[i].input = inputs[i];

		if (resolve_target(inputs[i], &tmp[i].addr) == FAILURE)
		{
			return FAILURE;
		}

		tmp[i].hostname = reverse_dns(tmp[i].addr);
		tmp[i].last_udp_sent = (struct timeval){ 0, 0 };
	}

	return SUCCESS;
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

static int parse_port_strict(const char *s, u16 *out)
{
	if (!s || !*s)
		return FAILURE; // empty input is not a valid port

	errno = 0;
	char	  *end = NULL;
	const long value = strtol(s, &end, 10);

	if (errno == ERANGE)
		return FAILURE; // overflow/underflow
	if (end == s)
		return FAILURE; // no digits parsed
	if (*end != '\0')
		return FAILURE; // extra characters after number

	if (value < MIN_PORT_NUMBER || value > MAX_PORT_NUMBER)
	{
		return FAILURE;
	}

	*out = (u16)value;
	return SUCCESS;
}

static bool contains_port(const u16 *ports, const size_t count, const u16 port)
{
	for (size_t i = 0; i < count; i++)
		if (ports[i] == port)
			return true;
	return false;
}

static int push_port(u16 *ports, u16 *count, const u16 port,
					 bool *duplicate_port_number)
{
	bool duplicate = contains_port(ports, *count, port);

	*duplicate_port_number |= duplicate;
	if (*count >= MAX_PORT_COUNT)
		return FAILURE;

	if (duplicate == false)
	{
		ports[*count] = port;
		(*count)++;
	}
	return SUCCESS;
}

static int parse_token_and_push(char *token, u16 *ports, u16 *count,
								bool *duplicate_port_number)
{
	char *dash = strchr(token, '-');

	if (!dash)
	{
		u16 port;
		if (parse_port_strict(token, &port) == FAILURE)
		{
			LOG("ft_nmap: invalid port: '%s'\n", token);
			return FAILURE;
		}
		if (push_port(ports, count, port, duplicate_port_number) == FAILURE)
		{
			LOG("ft_nmap: too many ports (max %d)\n", MAX_PORT_COUNT);
			return FAILURE;
		}
		return SUCCESS;
	}

	if (strchr(dash + 1, '-') != NULL)
	{
		LOG("ft_nmap: invalid port range: '%s'\n", token);
		return FAILURE;
	}

	*dash = '\0';
	char *left = token;
	char *right = dash + 1;

	if (*left == '\0' || *right == '\0')
	{
		LOG("ft_nmap: invalid port range: '%s-%s'\n", left, right);
		return FAILURE;
	}

	u16 port_left, port_right;
	if (parse_port_strict(left, &port_left) == FAILURE
		|| parse_port_strict(right, &port_right) == FAILURE)
	{
		LOG("ft_nmap: invalid port range: '%s-%s'\n", left, right);
		return FAILURE;
	}

	if (port_left > port_right)
	{
		LOG("ft_nmap: Your port range %d-%d is backwards. Did you mean %d-%d ?\n",
			port_left, port_right, port_left, port_right);
		return FAILURE;
	}

	if (port_right - port_left > 1024)
	{
		LOG("ft_nmap: too many ports (max %d)\n", MAX_PORT_COUNT);
		return FAILURE;
	}

	for (u32 port = port_left; port <= port_right; port++)
	{
		if (push_port(ports, count, (u16)port, duplicate_port_number)
			== FAILURE)
		{
			LOG("ft_nmap: too many ports (max %d)\n", MAX_PORT_COUNT);
			return FAILURE;
		}
	}

	return SUCCESS;
}

int parse_ports(const char *port_str, u16 *ports, u16 *port_count)
{
	*port_count = 0;
	bool duplicate_port_number = false;

	char *copy = strdup(port_str);
	if (!copy)
	{
		LOG("ft_nmap: strdup failed: %s\n", strerror(errno));
		return FAILURE;
	}

	int error = SUCCESS;

	char *tok = strtok(copy, ",");
	while (tok != NULL)
	{
		char *trim_str = trim_inplace(tok);

		if (!trim_str || *trim_str == '\0')
		{
			LOG("ft_nmap: invalid empty port token in: '%s'\n", port_str);
			error = FAILURE;
			break;
		}

		if (parse_token_and_push(trim_str, ports, port_count,
								 &duplicate_port_number)
			== FAILURE)
		{
			error = FAILURE;
			break;
		}

		tok = strtok(NULL, ",");
	}
	if (duplicate_port_number)
	{
		LOG("ft_nmap: Duplicate port number(s) specified.\n");
	}
	free(copy);
	return error;
}

static int parse_scan_type(char *scan_str, u8 *out)
{
	char upper_scan_str[strlen(scan_str) + 1];
	strcpy(upper_scan_str, scan_str);

	for (size_t i = 0; upper_scan_str[i]; i++)
		upper_scan_str[i] = (char)toupper((unsigned char)upper_scan_str[i]);

	if (strcmp(upper_scan_str, "SYN") == 0)
	{
		*out = SCAN_SYN;
		return SUCCESS;
	}
	if (strcmp(upper_scan_str, "NULL") == 0)
	{
		*out = SCAN_NULL;
		return SUCCESS;
	}
	if (strcmp(upper_scan_str, "ACK") == 0)
	{
		*out = SCAN_ACK;
		return SUCCESS;
	}
	if (strcmp(upper_scan_str, "FIN") == 0)
	{
		*out = SCAN_FIN;
		return SUCCESS;
	}
	if (strcmp(upper_scan_str, "XMAS") == 0)
	{
		*out = SCAN_XMAS;
		return SUCCESS;
	}
	if (strcmp(upper_scan_str, "UDP") == 0)
	{
		*out = SCAN_UDP;
		return SUCCESS;
	}
	LOG("ft_nmap: invalid scan type: '%s'\n", scan_str);
	return FAILURE;
}

int parse_scan_types(char *scan_str, u8 (*out)[MAX_NB_SCAN_TYPE],
					 u8 *nb_scan_types, bool *tcp_scan, bool *udp_scan)
{
	char *saveptr = NULL;
	char *token = NULL;
	u8	  scan_type = 0;

	do
	{
		if (saveptr == NULL)
		{
			token = strtok_r(scan_str, ",", &saveptr);
		}
		else
		{
			token = strtok_r(NULL, ",", &saveptr);
		}
		if (token)
		{
			if (parse_scan_type(token, &scan_type) == FAILURE)
			{
				return FAILURE;
			}
			/* Reject duplicates and bound the write into out[]. */
			for (u8 i = 0; i < *nb_scan_types; i++)
			{
				if ((*out)[i] == scan_type)
				{
					LOG("ft_nmap: duplicate scan type: '%s'\n", token);
					return FAILURE;
				}
			}
			if (*nb_scan_types >= MAX_NB_SCAN_TYPE)
			{
				LOG("ft_nmap: too many scan types (max %d)\n",
					MAX_NB_SCAN_TYPE);
				return FAILURE;
			}
			(*out)[*nb_scan_types] = scan_type;
			if (scan_type == SCAN_UDP)
			{
				*udp_scan = true;
			}
			else
			{
				*tcp_scan = true;
			}
		}
		else if (token == NULL)
		{
			return *nb_scan_types == 0 ? FAILURE : SUCCESS;
		}
		(*nb_scan_types)++;
	} while (saveptr != NULL);
	return SUCCESS;
}

static int parse_decoys(const char *decoy_str, struct in_addr *decoys,
						u8 *decoy_count)
{
	char *copy = strdup(decoy_str);
	if (!copy)
	{
		LOG("ft_nmap: strdup failed: %s\n", strerror(errno));
		return FAILURE;
	}

	int	  error = SUCCESS;
	char *tok = strtok(copy, ",");
	while (tok != NULL)
	{
		char *trimmed = trim_inplace(tok);
		if (!trimmed || *trimmed == '\0')
		{
			LOG("ft_nmap: empty token in decoy list\n");
			error = FAILURE;
			break;
		}
		if (*decoy_count >= MAX_DECOYS)
		{
			LOG("ft_nmap: too many decoys (max %d)\n", MAX_DECOYS);
			error = FAILURE;
			break;
		}
		// ME: sentinel (INADDR_ANY = 0.0.0.0) marks where our real IP goes in
		// the sequence
		if (strcasecmp(trimmed, "ME") == 0)
		{
			decoys[(*decoy_count)++] = (struct in_addr){ .s_addr = INADDR_ANY };
			tok = strtok(NULL, ",");
			continue;
		}

		struct addrinfo	 hints;
		struct addrinfo *res = NULL;
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_INET;
		const int rc = getaddrinfo(trimmed, NULL, &hints, &res);
		if (rc != 0)
		{
			LOG("ft_nmap: invalid decoy address '%s': %s\n", trimmed,
				gai_strerror(rc));
			error = FAILURE;
			break;
		}
		memcpy(&decoys[*decoy_count],
			   &((struct sockaddr_in *)res->ai_addr)->sin_addr,
			   sizeof(struct in_addr));
		freeaddrinfo(res);
		(*decoy_count)++;
		tok = strtok(NULL, ",");
	}

	free(copy);
	return error;
}

static int parse_speed_strict(const char *str, u8 *out)
{
	while (isspace((unsigned char)*str))
		str++;

	if (*str == '\0' || *str == '-' || *str == '+')
	{
		LOG("ft_nmap: invalid speed value: '%s'\n", str);
		return FAILURE;
	}

	errno = 0;
	char		 *end = NULL;
	unsigned long value = strtoul(str, &end, 10);

	if (errno != 0 || end == str)
	{
		LOG("ft_nmap: invalid speed value: '%s'\n", str);
		return FAILURE;
	}

	while (isspace((unsigned char)*end))
		end++;

	if (*end != '\0')
	{
		LOG("ft_nmap: invalid characters in speed value: '%s'\n", str);
		return FAILURE;
	}

	if (value > SPEED_MAX)
	{
		LOG("ft_nmap: speed must be between %d and %d\n", SPEED_MIN, SPEED_MAX);
		return FAILURE;
	}

	*out = (u8)value;
	return SUCCESS;
}

int parse_max_retries(const char *str, u8 *out)
{
	while (isspace((unsigned char)*str))
		str++;

	if (*str == '\0' || *str == '-' || *str == '+')
	{
		LOG("ft_nmap: invalid speed value: '%s'\n", str);
		return FAILURE;
	}

	errno = 0;
	char		 *end = NULL;
	unsigned long value = strtoul(str, &end, 10);

	if (errno != 0 || end == str)
	{
		LOG("ft_nmap: invalid speed value: '%s'\n", str);
		return FAILURE;
	}

	while (isspace((unsigned char)*end))
		end++;

	if (*end != '\0')
	{
		LOG("ft_nmap: invalid characters in max-retries value: '%s'\n", str);
		return FAILURE;
	}

	if (value > MAX_RETRIES_MAX)
	{
		LOG("ft_nmap: max-retries must be between %d and %d\n", MAX_RETRIES_MIN, MAX_RETRIES_MAX);
		return FAILURE;
	}

	*out = (u8)value;
	return SUCCESS;
}

int parse_timeout_ms(const char *str, double *out)
{
		while (isspace((unsigned char)*str))
		str++;

	if (*str == '\0' || *str == '-' || *str == '+')
	{
		LOG("ft_nmap: invalid speed value: '%s'\n", str);
		return FAILURE;
	}

	errno = 0;
	char		 *end = NULL;
	double value = strtod(str, &end);

	if (errno != 0 || end == str)
	{
		LOG("ft_nmap: invalid speed value: '%s'\n", str);
		return FAILURE;
	}

	while (isspace((unsigned char)*end))
		end++;

	if (*end != '\0')
	{
		LOG("ft_nmap: invalid characters in timeout value: '%s'\n", str);
		return FAILURE;
	}

	if (value > TIMEOUT_MS_MAX)
	{
		LOG("ft_nmap: timeout must be between %d ms and %d ms\n", TIMEOUT_MS_MIN, TIMEOUT_MS_MAX);
		return FAILURE;
	}

	*out = value;
	return SUCCESS;
}


int parse_args(int argc, char **argv, t_args *args, char ***targets_input,
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
		{ "packet-trace", no_argument, 0, PACKET_TRACE },
		{ "reason", no_argument, 0, REASON },
		{ "verbose", no_argument, 0, VERBOSE },
		{ "decoy", required_argument, 0, DECOY },
		{ "traceroute", no_argument, 0, TRACEROUTE },
		{ "traceroute-icmp", no_argument, 0, TRACEROUTE_ICMP },
		{ "max-retries", required_argument, 0, MAX_RETRIES },
		{ "timeout", required_argument, 0, TIMEOUT_MS },
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
								  args->flags)
				== FAILURE)
				return FAILURE;
			break;

		case FILE_MODE:
			SET(args->flags, F_FILE_MODE);
			if (get_targets_input(optarg, target_count, targets_input,
								  FILE_MODE, args->flags)
				== FAILURE)
				return FAILURE;
			break;

		case PORTS:
			SET(args->flags, F_PORTS);
			if (parse_ports(optarg, args->ports, &args->port_count) == FAILURE)
				return FAILURE;
			break;

		case SCAN:
			SET(args->flags, F_SCAN_TYPE);
			if (parse_scan_types(optarg, &args->scan_types,
								 &args->nb_scan_types, &args->tcp_scan,
								 &args->udp_scan)
				== FAILURE)
			{
				return FAILURE;
			}
			break;

		case SPEED:
			SET(args->flags, F_SPEED);
			if (parse_speed_strict(optarg, &args->speed) == FAILURE)
				return FAILURE;
			break;

		case PACKET_TRACE:
			SET(args->flags, F_PACKET_TRACE);
			break;

		case REASON:
			SET(args->flags, F_REASON);
			break;

		case VERBOSE:
			SET(args->flags, F_VERBOSE);
			break;

		case DECOY:
			SET(args->flags, F_DECOY);
			if (parse_decoys(optarg, args->decoys, &args->decoy_count)
				== FAILURE)
				return FAILURE;
			break;

		case TRACEROUTE:
			SET(args->flags, F_TRACEROUTE);
			break;

		case TRACEROUTE_ICMP:
			SET(args->flags, F_TRACEROUTE_ICMP);
			break;

		case MAX_RETRIES:
			SET(args->flags, F_MAX_RETRIES);
			if (parse_max_retries(optarg, &args->max_retries) == FAILURE)
				return FAILURE;
			break;

		case TIMEOUT_MS:
			SET(args->flags, F_TIMEOUT_MS);
			if (parse_timeout_ms(optarg, &args->timeout_ms) == FAILURE)
				return FAILURE;
			break;

		case '?':
		case ':':
			LOG("ft_nmap: Invalid arguments. Use --help for usage "
				"information.\n");
			return FAILURE;
		default:
			break;
		}
	}
	if (optind < argc)
	{
		LOG("ft_nmap: unexpected argument: %s\n", argv[optind]);
		return FAILURE;
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

	if (HAS(args->flags, F_TIMEOUT_MS))
	{
		 args->timeout_s = (args->timeout_ms / 1000);
	}
	else
	{
		args->timeout_s = DEFAULT_TIMEOUT_DELAY_S;
	}
	if (HAS(args->flags, F_MAX_RETRIES) == false)
	{
		args->max_retries = DEFAULT_SCAN_RETRIES;
	}
	return SUCCESS;
}
