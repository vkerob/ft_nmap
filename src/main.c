#include "ft_nmap.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int main(int argc, char **argv)
{
	if (geteuid() != 0)
	{
		fprintf(stderr, "ft_nmap: You must be root to run this program.\n");
		return 1;
	}

	t_args args;
	memset(&args, 0, sizeof(args));
    if (parse_args(argc, argv, &args))
        return 1;

    t_ctx ctx;
	memset(&ctx, 0, sizeof(ctx));
    ctx.target_count = args.target_count;

    if (!resolve_targets(args.targets_input, args.target_count, &ctx.targets))
    {
        free_tabp((void ***)&args.targets_input, args.target_count);
        return 1;
    }

    free_tabp((void ***)&args.targets_input, args.target_count);

    for (size_t i = 0; i < ctx.target_count; i++)
        printf("Resolved target %zu: %s (%s)\n", i, ctx.targets[i].input, ctx.targets[i].ip);

    free_targets(&ctx.targets, ctx.target_count);
    return 0;
	// if (init_socket() != 0)
	// 	return 1;

	// if (setup_signal_handlers() != 0)
	// 	goto error;

	// if (run_nmap() != 0)
	// 	goto error;

	// error:
	// 	return 1;
}
