#ifndef FT_NMAP_H
#define FT_NMAP_H

#include "parsing.h"

#include <pcap/pcap.h>
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

typedef struct	s_target
{
	char						*input;
	char						ip[INET_ADDRSTRLEN];
	struct in_addr	addr;
}	t_target;

typedef struct	s_args
{
	uint8_t		flags;
	size_t		target_count;

	uint16_t	ports[MAX_PORTS_COUNT];
	size_t		port_count;

	uint8_t		scan_type;
	uint8_t		speed;
}	t_args;

typedef struct	s_socket
{
	int									sfd;
	int									source_port;
	struct sockaddr_in	sin;
}	t_socket;

typedef struct	s_ctx
{
	t_socket					socket;
	t_target					*targets;
	size_t						target_count;
	struct in_addr		my_ip;
	char							*dev_name;
	t_args						args;
}	t_ctx;

typedef struct	s_ip_pseudo_hdr
{
	struct  in_addr ip_src, ip_dst;  /* source and dest address */
	uint8_t					zero;
	uint8_t					protocol;
	uint16_t				tcp_length;
}	t_ip_pseudo_hdr;

typedef struct	s_ethernet_hdr
{
	uint8_t		dst_mac_addr[6];
	uint8_t		src_mac_addr[6];
	uint16_t	protocol;
}	t_ethernet_hdr;

/* Socket */
int				init_socket(t_socket *sock);
void			close_socket(t_socket socket);
void			update_socket(struct sockaddr_in *socket, t_target target, uint16_t port);

/* Debug */
void			print_ip_header(struct ip *ip_hdr);

/* TCP / IP */
void			fill_pseudo_ip_header(t_ip_pseudo_hdr *ip_pseudo_hdr);
void			fill_tcp_header(struct tcphdr *tcp_hdr);
uint16_t	calculate_checksum(uint16_t *buffer, int len);
void			calculate_tcp_checksum(t_ip_pseudo_hdr *ip_pseudo_hdr, struct tcphdr *tcp_hdr);
void			set_default_headers(char *buffer, t_ip_pseudo_hdr *ip_pseudo_hdr);
void			print_tcp_header(struct tcphdr *tcp_hdr);
void			print_ip_header(struct ip *ip_hdr);
void			update_port_tcp(struct tcphdr *tcp_hdr, uint16_t port);
void			update_ip_headers_dst_addr(
		t_ip_pseudo_hdr *ip_pseudo_hdr,
		struct in_addr dst_addr);
int				send_packet(t_socket socket, char *datagram);

/* Scan */
int				run_scan(t_ctx ctx, t_socket socket, char *datagram);

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
int				set_pcap_filter(pcap_t *interface);
struct ip	decode_ip_packet(uint8_t *datagram);

#endif /* FT_NMAP_H */
