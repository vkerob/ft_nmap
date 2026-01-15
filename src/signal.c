#include "ft_nmap.h"
#include <signal.h>
#include <string.h>
#include <stdio.h>

void handle_signal(int signum)
{
	(void)signum;
	// g_stop = 1;
}

bool setup_signal_handlers(void)
{
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = handle_signal;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;

	if (sigaction(SIGINT, &sa, NULL) != 0)
	{
		perror("sigaction(SIGINT)");
		return true;
	}

	if (sigaction(SIGTERM, &sa, NULL) != 0)
	{
		perror("sigaction(SIGTERM)");
		return true;
	}

	return false;
}