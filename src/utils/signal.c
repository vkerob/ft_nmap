#include "my_signal.h"
#include "defines.h"

#include <signal.h>
#include <stdio.h>
#include <string.h>

void	handle_signal(int signum)
{
	(void)signum;
	g_stop = 1;
}

int	setup_signal_handlers(void)
{
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = handle_signal;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;

	if (sigaction(SIGINT, &sa, NULL) != 0)
	{
		perror("sigaction(SIGINT)");
		return FAILURE;
	}

	if (sigaction(SIGTERM, &sa, NULL) != 0)
	{
		perror("sigaction(SIGTERM)");
		return FAILURE;
	}

	return SUCCESS;
}
