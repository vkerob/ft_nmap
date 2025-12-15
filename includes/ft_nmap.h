#ifndef FT_NMAP_H
#define FT_NMAP_H

#include <signal.h>
#include <stdint.h>

extern volatile sig_atomic_t g_stop;

#define SET(flags, flag) ((flags) |= (flag))
#define HAS(flags, flag) (((flags) & (flag)) != 0)

enum e_flags
{
	F_HELP = 1u << 0
};

typedef struct s_args
{
	uint8_t flags;

	const char *host;
} t_args;

typedef struct s_ctx
{
	int sockfd;
} t_ctx;

#endif /* FT_NMAP_H */
