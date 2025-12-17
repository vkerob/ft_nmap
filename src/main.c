#include "ft_nmap.h"
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
	if (geteuid() != 0)
	{
		fprintf(stderr, "ft_nmap: You must be root to run this program.\n");
		return 1;
	}

	t_args args;
	if (parse_args(argc, argv, &args))
		return 1;

	if (resolve_hosts(args.targets_input, args.target_count, &args.targets_addr,
					  &args.targets_ip)
		== false)
	{
		free_tabp((void ***)&args.targets_input, args.target_count);
		return 1;
	}
	for (size_t i = 0; i < args.target_count; i++)
	{
		printf("Resolved target %zu: %s\n", i, args.targets_ip[i]); // debug
	}

	free_tabp((void ***)&args.targets_input, args.target_count);
	free_tabp((void ***)&args.targets_ip, args.target_count);
	free(args.targets_addr);
	args.targets_addr = NULL;

	// if (init_socket() != 0)
	// 	return 1;

	// if (setup_signal_handlers() != 0)
	// 	goto error;

	// if (run_nmap() != 0)
	// 	goto error;

	return 0;

	// error:
	// 	return 1;
}
