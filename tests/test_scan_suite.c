#include "greatest.h"
#include "tests.h"
#include <errno.h>
#include <regex.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
SUITE(scan_suite);
extern t_server *g_server_data; // just the variable, extern is fine here

#define die(e)                                                                 \
	do                                                                         \
	{                                                                          \
		fprintf(stderr, "%s\n", e);                                            \
		exit(EXIT_FAILURE);                                                    \
	} while (0);

void run_command(char **args, char **output)
{
	(void)args;
	int pipe_fds[2];
	(void)output;
	if (pipe(pipe_fds) == -1)
	{
		fprintf(stderr, "%s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	pid_t pid = fork();

	if (pid == 0)
	{
		dup2(pipe_fds[1], STDOUT_FILENO);
		close(pipe_fds[0]);
		close(pipe_fds[1]);
		if (execve(args[0], args, NULL) == -1)
		{
			fprintf(stderr, "%s\n", strerror(errno));
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

#define NITEMS(arr) (sizeof((arr)) / sizeof((arr)[0]))

char *substr(char *str, int start, int end)
{
	int	  len = end - start;
	char *new = calloc(len, sizeof(char));
	strncpy(new, str + start, len);
	return new;
}

typedef struct s_port
{
	int			   port;
	char		  *port_state;
	struct s_port *next;
} t_port;

void get_port_list(char *ft_nmap_output, regex_t regex, t_port **head)
{
	char	  *ptr = ft_nmap_output;
	t_port	  *tmp = NULL;
	regmatch_t pmatch[3];

	for (unsigned int i = 0;; i++)
	{
		if (regexec(&regex, ptr, 3, pmatch, 0))
			break;

		char *port_nbr_str = substr(ptr, pmatch[1].rm_so, pmatch[1].rm_eo);
		char *state_str = substr(ptr, pmatch[2].rm_so, pmatch[2].rm_eo);

		int		port = atoi(port_nbr_str);
		t_port *new = calloc(1, sizeof(t_port));

		new->port_state = state_str;
		new->port = port;
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
		ptr += pmatch[2].rm_eo;
		memset(pmatch, 0, sizeof(pmatch));
	}
}

TEST compare(char *ft_nmap_output, char *nmap_output, const char *protocol)
{
	regex_t regex;
	t_port *port_list_nmap = NULL;
	t_port *port_list_ft_nmap = NULL;

	char re[512] = { 0 };

	/* Match the following type of line:
		1234/tcp closed hotline
	*/
	sprintf(re, "([0-9]+)/%s.*(closed|open|filtered|unfiltered)", protocol);
	if (regcomp(&regex, re, REG_NEWLINE | REG_EXTENDED))
	{
		exit(EXIT_FAILURE);
	}

	get_port_list(ft_nmap_output, regex, &port_list_ft_nmap);
	get_port_list(nmap_output, regex, &port_list_nmap);

	t_port *tmp1 = port_list_nmap;
	t_port *tmp2 = port_list_ft_nmap;

	while (tmp1 && tmp2)
	{
		ASSERT_EQ(tmp1->port, tmp2->port);
		ASSERT_STR_EQ(tmp1->port_state, tmp2->port_state);
		tmp1 = tmp1->next;
		tmp2 = tmp2->next;
	}
	PASS();
}

void run_test(char **args_nmap, char **args_ft_nmap, const char *protocol)
{
	char *ft_nmap_output = NULL;
	char *nmap_output = NULL;

	run_command(args_ft_nmap, &ft_nmap_output);
	run_command(args_nmap, &nmap_output);

	compare(ft_nmap_output, nmap_output, protocol);
}

SUITE(scan_suite)
{
	char *args_nmap[]
		= { "/usr/bin/nmap", "127.0.0.1", "-p", g_server_data->tcp_arg_port,
			"-sS",			 NULL };
	char *args_ft_nmap[] = { "./ft_nmap",
							 "--ip",
							 "127.0.0.1",
							 "--ports",
							 g_server_data->tcp_arg_port,
							 "--scan",
							 "SYN",
							 NULL };
	run_test(args_nmap, args_ft_nmap, "tcp");
}
