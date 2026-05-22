#include "greatest.h"
#include "tests.h"
#include "typesdef.h"
#include <errno.h>
#include <regex.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

// Size of data type use to represent one unit of text
#define PCRE2_CODE_UNIT_WIDTH 8

#include <pcre2.h>

extern char **environ;

#define NITEMS(arr) (sizeof((arr)) / sizeof((arr)[0]))

SUITE(scan_suite);

extern t_server *g_server_data; // just the variable, extern is fine here

void run_command(char **args, char **output)
{
	int pipe_fds[2];

	if (pipe(pipe_fds) == -1)
	{
		fprintf(stderr, "%s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	printf("Executing following commands: \n");
	for (int i = 0; args[i]; i++)
	{
		printf("%s ", args[i]);
	}
	printf("\n");
	pid_t pid = fork();

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
			if (*output == NULL)
			{
				*output = strndup(buf, nbytes);
			}
			else
			{
				size_t old_len = strlen(*output);
				char  *new_output = calloc(old_len + nbytes + 1, sizeof(char));
				strncpy(new_output, *output, old_len);
				strncat(new_output + old_len, buf, nbytes);
				free(*output);
				*output = new_output;
			}
			memset(buf, 0, sizeof(buf));
		}
		close(pipe_fds[0]);
		wait(NULL);
	}
}

char *substr(char *str, int start, int end)
{
	int	  len = end - start;
	char *new = calloc(len, sizeof(char));
	if (new == NULL)
	{
		fprintf(stderr, "%s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	strncpy(new, str + start, len);
	return new;
}

typedef struct s_port
{
	char 			*port;
	char		  *port_state;
	char		  *service;
	char			*protocol;
	struct s_port *next;
} t_port;

static void free_port(t_port *port)
{
	free(port->port_state);
	free(port->service);
	free(port->protocol);
	free(port->port);
	free(port);
}

static void get_port_list(char *ft_nmap_output, pcre2_code *regex, t_port **head)
{
	t_port	  *tmp = NULL;

	char *ptr = ft_nmap_output;

	/* Match the pattern against the subject text. */

	while(1)
	{
		pcre2_match_data *match_data =
		pcre2_match_data_create_from_pattern(regex, NULL);
		int  rc = pcre2_match(
			regex,
			(unsigned char *)ptr,
			strlen(ptr),
			0,
			0,
			match_data,
			NULL);
		if (rc == PCRE2_ERROR_NOMATCH) {
			break ;
		} else if (rc < 0) {
			fprintf(stderr, "Matching error\n");
			break ;
		} else {
			PCRE2_SIZE *ovector = pcre2_get_ovector_pointer(match_data);

			char *port_nb_str = substr(ptr, ovector[2], ovector[3]);
			char *protocol = substr(ptr, ovector[4], ovector[5]);
			char *state_str = substr(ptr, ovector[6], ovector[7]);
			char *service_str = substr(ptr, ovector[8], ovector[9]);

			t_port *new = calloc(1, sizeof(t_port));
			if (new == NULL)
			{
				fprintf(stderr, "%s\n", strerror(errno));
				exit(EXIT_FAILURE);
			}
			new->port_state = state_str;
			new->port = port_nb_str;
			new->service = service_str;
			new->protocol = protocol;
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
			ptr += ovector[1];
		}
		pcre2_match_data_free(match_data);   /* Free resources */
	}
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

#define OVECCOUNT 30    /* should be a multiple of 3 */


TEST compare(char **args_nmap, char **args_ft_nmap, const char *protocol)
{
	// regex_t regex;
	t_port *port_list_nmap = NULL;
	t_port *port_list_ft_nmap = NULL;
// int ovector[OVECCOUNT];

	char *ft_nmap_output = NULL;
	char *nmap_output = NULL;

	run_command(args_ft_nmap, &ft_nmap_output);
	run_command(args_nmap, &nmap_output);
	char pattern[512] = { 0 };

	/* Match the following type of line:
		1234/tcp closed hotline
	*/
	// sprintf( re,
	// 	"([0-9]+)/%s.*\\(closed|open|filtered|unfiltered\\) \\((?:[a-zA-Z]|[0-9]|-)*\\)",
	// 	protocol);
	(void)protocol;
	sprintf(pattern,
		"([0-9]+)\\/(tcp|udp)\\s*(closed|open|filtered|unfiltered)\\s*(unknown|[a-zA-Z0-9]*)\\s*\\n");  // substitute your actual value here
	int error_number;
	PCRE2_SIZE error_offset;
	pcre2_code *re = pcre2_compile(
		(unsigned char *)pattern,               /* the pattern */
		PCRE2_EXTENDED | PCRE2_NEWLINE_ANY | PCRE2_ZERO_TERMINATED, /* indicates pattern is zero-terminated */
		0,                     /* default options */
		&error_number,         /* for error number */
		&error_offset,         /* for error offset */
		NULL);   
	if (re == NULL)
	{
		fprintf(stderr, "Invalid pattern: %s\n", pattern);
		exit(EXIT_FAILURE);
	}
	get_port_list(ft_nmap_output, re, &port_list_ft_nmap);
	get_port_list(nmap_output, re, &port_list_nmap);
	pcre2_code_free(re);


	u16 size_port_list_ft_nmap = get_port_list_size(port_list_ft_nmap);
	u16 size_port_list_nmap = get_port_list_size(port_list_nmap);

	ASSERT_EQ(size_port_list_ft_nmap, size_port_list_nmap);
	t_port *tmp1 = port_list_nmap;
	t_port *tmp2 = port_list_ft_nmap;

	while (tmp1 && tmp2)
	{
		ASSERT_STR_EQ(tmp1->port, tmp2->port);
		ASSERT_STR_EQ(tmp1->port_state, tmp2->port_state);
		// ASSERT_STR_EQ(tmp1->service, tmp2->service);
		ASSERT_STR_EQ(tmp1->protocol, tmp2->protocol);

		tmp1 = tmp1->next;
		tmp2 = tmp2->next;
	}

	free_port_list(port_list_nmap);
	free_port_list(port_list_ft_nmap);

	PASS();
}

SUITE(scan_suite)
{
	// char *args[] = { "/usr/bin/nmap",		   "127.0.0.1", "-p",
	// 				 g_server_data->udp_ports, "-sU",		NULL };
	// char *ft_nmap_args[] = {
	// 	"./ft_nmap", "--ip", "127.0.0.1", "--ports", g_server_data->udp_ports,
	// 	"--scan",	 "UDP",	 NULL
	// };
	// RUN_TESTp(compare, args, ft_nmap_args, "udp");

	char *args2[] = { "/usr/bin/nmap",			"127.0.0.1", "-p",
					  g_server_data->tcp_ports, "-sS",		 NULL };
	char *ft_nmap_args2[] = {
		"./ft_nmap", "--ip", "127.0.0.1", "--ports", g_server_data->tcp_ports,
		"--scan",	 "SYN",	 NULL
	};
	RUN_TESTp(compare, args2, ft_nmap_args2, "tcp");

}
