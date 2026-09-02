#include "greatest.h"
#include "tests.h"
#include "typesdef.h"
#include "utils.h"

#include <errno.h>
#include <regex.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

// Size of data type use to represent one unit of text
#define PCRE2_CODE_UNIT_WIDTH 8

#include <pcre2.h>

SUITE(scan_udp_suite);
SUITE(scan_syn_suite);
SUITE(scan_ack_suite);
SUITE(scan_stealth_suite);

extern t_server *g_server_data;

bool run_command(char **args, char **output)
{
	int	  pipe_fds[2];
	pid_t pid;

	if (pipe(pipe_fds) == -1)
	{
		fprintf(stderr, "%s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	pid = fork();
	if (pid == 0)
	{
		dup2(pipe_fds[1], STDOUT_FILENO);
		close(pipe_fds[0]);
		close(pipe_fds[1]);

		if (execvp(args[0], args) == -1)
		{
			fprintf(stderr, "|%s|\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
	}
	else
	{
		int	 nbytes = 0;
		char buf[4096] = { 0 };
		close(pipe_fds[1]);

		while (0 != (nbytes = read(pipe_fds[0], buf, sizeof(buf))))
		{
			if (nbytes < 0)
			{
				if (errno == EINTR)
				{
					continue;
				}
				close(pipe_fds[0]);
				wait(NULL);
				perror("read");
				return true;
			}
			if (*output == NULL)
			{
				*output = strndup(buf, nbytes);
				if (output == NULL)
				{
					LOG("test_ft_nmap: calloc failed: %s\n", strerror(errno));
					close(pipe_fds[0]);
					wait(NULL);
					return true;
				}
			}
			else
			{
				size_t old_len = strlen(*output);
				char  *new_output = calloc(old_len + nbytes + 1, sizeof(char));
				if (new_output == NULL)
				{
					LOG("test_ft_nmap: calloc failed: %s\n", strerror(errno));
					close(pipe_fds[0]);
					wait(NULL);
					free(*output);
					return true;
				}
				strncpy(new_output, *output, old_len);
				strncat(new_output + old_len, buf, nbytes);
				free(*output);
				*output = new_output;
			}
			memset(buf, 0, sizeof(buf));
		}
		close(pipe_fds[0]);
		waitpid(pid, NULL, 0);

	}
	return false;
}

static void free_port(t_port *port)
{
	free(port->port_state);
	free(port->service);
	free(port->protocol);
	free(port->port);
	free(port);
}

static bool get_port_list(char *subject, pcre2_code *regex, t_port **head)
{
	t_port *tmp = NULL;
	char   *ptr = subject;
	int		rc;

	/* Match the pattern against the subject text. */
	while (1)
	{
		pcre2_match_data *match_data
			= pcre2_match_data_create_from_pattern(regex, NULL);
		rc = pcre2_match(regex, (unsigned char *)ptr, strlen(ptr), 0, 0,
						 match_data, NULL);
		if (rc == PCRE2_ERROR_NOMATCH)
		{
			break;
		}
		else if (rc < 0)
		{
			fprintf(stderr, "Matching error\n");
			break;
		}
		else
		{
			PCRE2_SIZE *ovector = pcre2_get_ovector_pointer(match_data);
			if (ovector == NULL)
			{
				fprintf(stderr, "%s\n", strerror(errno));
				pcre2_match_data_free(match_data);
				return true;
			}

			t_port *new = calloc(1, sizeof(t_port));
			if (new == NULL)
			{
				fprintf(stderr, "%s\n", strerror(errno));
				pcre2_match_data_free(match_data);
				return true;
			}
			if (*head)
			{
				tmp->next = new;
				tmp = new;
			}
			else
			{
				*head = new;
				tmp = *head;
			}

			if (substr(ptr, ovector[2], ovector[3], &new->port)
				|| substr(ptr, ovector[4], ovector[5], &new->protocol)
				|| substr(ptr, ovector[6], ovector[7], &new->port_state)
				|| substr(ptr, ovector[8], ovector[9], &new->service))
			{
				pcre2_match_data_free(match_data);
				return true;
			}
			ptr += ovector[1];
		}
		pcre2_match_data_free(match_data);
	}
	return false;
}

static u16 get_port_list_size(t_port *head)
{
	t_port *tmp = head;
	u16		i = 0;

	while (tmp)
	{
		i++;
		tmp = tmp->next;
	}
	return i;
}

static void free_port_list(t_port *head)
{
	t_port *tmp = head;
	t_port *prev;

	while (tmp)
	{
		prev = tmp;
		tmp = tmp->next;
		free_port(prev);
	}
}

TEST compare(char **args_nmap, char **args_ft_nmap)
{
	char		pattern[512] = { 0 };
	t_port	   *port_list_nmap = NULL;
	t_port	   *port_list_ft_nmap = NULL;
	char	   *ft_nmap_output = NULL;
	char	   *nmap_output = NULL;
	int			error_number;
	PCRE2_SIZE	error_offset;
	pcre2_code *re = NULL;

	if (run_command(args_ft_nmap, &ft_nmap_output)
		|| run_command(args_nmap, &nmap_output))
	{
		goto fail;
	}

	if (ft_nmap_output == NULL || nmap_output == NULL)
	{
		goto fail;
	}

	/* Match the following type of line:
		1234/tcp closed hotline
	*/
	snprintf(pattern, sizeof(pattern),
			 "([0-9]+)\\/"
			 "(tcp|udp)\\s*(closed|open\\|filtered|open|filtered|unfiltered)"
			 "\\s*(unknown|[a-zA-Z0-9-_]*)\\s*\\n");

	re = pcre2_compile(
		(unsigned char *)pattern, /* the pattern */
		PCRE2_ZERO_TERMINATED,	  /* indicates pattern is zero-terminated */
		0,						  /* default options */
		&error_number,			  /* for error number */
		&error_offset,			  /* for error offset */
		NULL);

	if (re == NULL)
	{
		fprintf(stderr, "Invalid pattern: %s\n", pattern);
		goto fail;
	}
	if (get_port_list(ft_nmap_output, re, &port_list_ft_nmap)
		|| get_port_list(nmap_output, re, &port_list_nmap))
	{
		pcre2_code_free(re);
		goto fail;
	}
	pcre2_code_free(re);

	u16 size_port_list_ft_nmap = get_port_list_size(port_list_ft_nmap);
	u16 size_port_list_nmap = get_port_list_size(port_list_nmap);

	if (size_port_list_ft_nmap == 0)
	{
		LOG("compare: ft_nmap output had no matching port lines\n");
		goto fail;
	}
	if (size_port_list_nmap == 0)
	{
		LOG("compare: nmap output had no matching port lines\n");
		goto fail;
	}
	ASSERT_EQ(size_port_list_ft_nmap, size_port_list_nmap);

	t_port *tmp1 = port_list_nmap;
	t_port *tmp2 = port_list_ft_nmap;

	while (tmp1 && tmp2)
	{
		ASSERT_STR_EQ(tmp1->port, tmp2->port);
		ASSERT_STR_EQ(tmp1->port_state, tmp2->port_state);
		ASSERT_STR_EQ(tmp1->service, tmp2->service);
		ASSERT_STR_EQ(tmp1->protocol, tmp2->protocol);

		tmp1 = tmp1->next;
		tmp2 = tmp2->next;
	}

	free_port_list(port_list_nmap);
	free_port_list(port_list_ft_nmap);
	pcre2_code_free(re);

	PASS();

fail:
	free_port_list(port_list_nmap);
	free_port_list(port_list_ft_nmap);
	pcre2_code_free(re);
	FAIL();
}


SUITE(scan_udp_suite)
{
	char *args_udp[]
		= { "/usr/bin/nmap", "127.0.0.1", "-p", g_server_data->udp_ports,
			"-sU",			 "-v",		  NULL };
	char *ft_nmap_args_udp[] = {
		"./ft_nmap", "--ip", "127.0.0.1", "--ports", g_server_data->udp_ports,
		"--scan",	 "UDP",	 "--verbose", NULL
	};
	RUN_TESTp(compare, args_udp, ft_nmap_args_udp);
}

SUITE(scan_syn_suite)
{
	/* Plain SYN */
	char *args_syn[]
		= { "/usr/bin/nmap", "127.0.0.1", "-p", g_server_data->tcp_ports,
			"-sS",			 "-v",		  NULL };
	char *ft_nmap_args_syn[] = {
		"./ft_nmap", "--ip",	  "127.0.0.1", "--ports", g_server_data->tcp_ports,
		"--scan",	 "SYN",	  "--verbose", NULL
	};
	RUN_TESTp(compare, args_syn, ft_nmap_args_syn);

	/* SYN with --speedup: verifies parallelism does not alter results */
	char *args_syn_speed[]
		= { "/usr/bin/nmap", "127.0.0.1", "-p", g_server_data->tcp_ports,
			"-sS",			 "-v",		  NULL };
	char *ft_nmap_args_syn_speed[] = {
		"./ft_nmap", "--ip",	  "127.0.0.1", "--ports", g_server_data->tcp_ports,
		"--scan",	 "SYN",	  "--speedup", "50", "--verbose", NULL
	};
	RUN_TESTp(compare, args_syn_speed, ft_nmap_args_syn_speed);

	/* SYN over a fixed 7-port range (below PRINT_LIMIT=25, usually all closed) */
	char *args_syn_range[]
		= { "/usr/bin/nmap", "127.0.0.1", "-p", "1024-1030",
			"-sS",			 "-v",		  NULL };
	char *ft_nmap_args_syn_range[] = {
		"./ft_nmap", "--ip",   "127.0.0.1", "--ports", "1024-1030",
		"--scan",	 "SYN",	  "--verbose", NULL
	};
	RUN_TESTp(compare, args_syn_range, ft_nmap_args_syn_range);
}

SUITE(scan_ack_suite)
{
	/* Fixed 7-port range keeps count below PRINT_LIMIT so both tools show
	 * individual port lines (all unfiltered on localhost without firewall). */
	char *args_ack[]
		= { "/usr/bin/nmap", "127.0.0.1", "-p", "1031-1037",
			"-sA",			 "-v",		  NULL };
	char *ft_nmap_args_ack[] = {
		"./ft_nmap", "--ip",	  "127.0.0.1", "--ports", "1031-1037",
		"--scan",	 "ACK",	  "--verbose", NULL
	};
	RUN_TESTp(compare, args_ack, ft_nmap_args_ack);
}

SUITE(scan_stealth_suite)
{
	/* FIN */
	char *args_fin[]
		= { "/usr/bin/nmap", "127.0.0.1", "-p", g_server_data->tcp_ports,
			"-sF",			 "-v",		  NULL };
	char *ft_nmap_args_fin[] = {
		"./ft_nmap", "--ip",	  "127.0.0.1", "--ports", g_server_data->tcp_ports,
		"--scan",	 "FIN",	  "--verbose", NULL
	};
	RUN_TESTp(compare, args_fin, ft_nmap_args_fin);

	/* XMAS */
	char *args_xmas[]
		= { "/usr/bin/nmap", "127.0.0.1", "-p", g_server_data->tcp_ports,
			"-sX",			 "-v",		  NULL };
	char *ft_nmap_args_xmas[] = {
		"./ft_nmap", "--ip",	  "127.0.0.1", "--ports", g_server_data->tcp_ports,
		"--scan",	 "XMAS",	  "--verbose", NULL
	};
	RUN_TESTp(compare, args_xmas, ft_nmap_args_xmas);

	/* NULL */
	char *args_null[]
		= { "/usr/bin/nmap", "127.0.0.1", "-p", g_server_data->tcp_ports,
			"-sN",			 "-v",		  NULL };
	char *ft_nmap_args_null[] = {
		"./ft_nmap", "--ip",	  "127.0.0.1", "--ports", g_server_data->tcp_ports,
		"--scan",	 "NULL",	  "--verbose", NULL
	};
	RUN_TESTp(compare, args_null, ft_nmap_args_null);
}
