#ifndef FT_NMAP_H
#define FT_NMAP_H

#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>

extern volatile sig_atomic_t g_stop;

#define SET(flags, flag) ((flags) |= (flag))
#define HAS(flags, flag) (((flags) & (flag)) != 0)

enum e_flags
{
	F_HELP = 1u << 0,
	F_IP_MODE = 1u << 1,
	F_FILE_MODE = 1u << 2,
	F_PORTS = 1u << 3,
	F_SCAN_TYPE = 1u << 4,
	F_SPEED = 1u << 5
};

enum e_scan_type
{
	SCAN_SYN,
	SCAN_NULL,
	SCAN_ACK,
	SCAN_FIN,
	SCAN_XMAS,
	SCAN_UDP
};

typedef struct s_args
{
	uint8_t flags;

	struct sockaddr_in *targets_addr;
	char			  **targets_input;
	char			  **targets_ip;
	size_t				target_count;

	uint16_t ports[1024];
	size_t	 port_count;

	uint8_t	 scan_type;
	uint16_t speed;

} t_args;

typedef struct s_ctx
{
	int sockfd;
} t_ctx;

bool   parse_args(int argc, char **argv, t_args *args);
char **get_targets_input(const char *arg, size_t *args_count, int mode);
bool   resolve_hosts(char **hosts, size_t host_count,
					 struct sockaddr_in **targets_addr, char ***targets_ip);
bool   resolve_host(const char *host, struct sockaddr_in *dst,
					char ipbuf[INET_ADDRSTRLEN]);
void   free_tabp(void ***ptab, size_t n);

#endif /* FT_NMAP_H */
