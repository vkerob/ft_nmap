#include "ft_nmap.h"
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	if (geteuid() != 0)
	{
		fprintf(stderr, "ft_nmap: You must be root to run this program.\n");
		return 1;
	}
	if (parse_args(argc, argv) != 0)
		return 1;

	if (resolve_host() != 0)
		return 1;

	if (init_socket() != 0)
		return 1;

	if (setup_signal_handlers() != 0)
		goto error;

	if (run_nmap() != 0)
		goto error;

	return 0;

error:
	return 1;
}
