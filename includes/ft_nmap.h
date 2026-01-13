#ifndef FT_NMAP_H
#define FT_NMAP_H

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <signal.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <netdb.h>
#include <limits.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

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

typedef struct s_target
{
	char						*input;
	char						ip[INET_ADDRSTRLEN];
	struct in_addr	addr;
} t_target;

typedef struct	s_args
{
	uint8_t		flags;
	size_t		target_count;

	uint16_t	ports[1024];
	size_t		port_count;

	uint8_t		scan_type;
	uint8_t		speed;
}	t_args;

typedef struct	s_socket {
	int	sfd;
	int	source_port;
}	t_socket;

typedef struct	s_ctx
{
	t_socket	socket;
	t_target	*targets;
	size_t		target_count;
	struct		in_addr my_ip;
	char			*dev_name;
	t_args		args;
}	t_ctx;


/* Socket */
int				init_socket(t_socket *sock);
void			close_socket(t_socket *socket);

/* TCP / IP */
void			fill_ip_header(struct ip *ip_hdr);
void			fill_tcp_header(struct tcphdr *tcp_hdr);
uint16_t	calculate_checksum(char *buffer, int len);
void			set_default_headers(char *buffer);
void			print_tcp_header(struct tcphdr *tcp_hdr);
void			print_ip_header(struct ip *ip_hdr);
void			update_port_tcp(struct tcphdr *tcp_hdr, uint16_t port);
void			update_ip_header_dst_addr(struct ip *ip_hdr, struct in_addr dst_addr);
void			update_ip_checksum(char *buffer);

/* Parsing */
bool			parse_args(int argc, char **argv, t_args *args, char ***targets_input);
bool			get_targets_input(const char *arg, size_t *args_count, char ***targets,
						int mode, uint8_t flags);
bool			resolve_targets(char **inputs, size_t count, t_target **out);
void			free_targets(t_target **pt, size_t count);
void			free_tabp(void ***ptab, size_t count);

/* Signal handlers */
bool			setup_signal_handlers(void);

/* Pcap wrapper */
bool			pcap_select_interface(char **dev_name, struct in_addr *my_ip);

#endif /* FT_NMAP_H */
