#ifndef FT_NMAP_H
#define FT_NMAP_H

#include "parsing.h"

#include <arpa/inet.h>
#include <limits.h>
#include <linux/if_ether.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define ANSI_COLOR_GREEN "\x1b[32m"
#define ANSI_COLOR_BLUE "\x1b[34m"
#define ANSI_COLOR_YELLOW "\x1b[33m"
#define ANSI_COLOR_CYAN "\x1b[36m"
#define ANSI_COLOR_RESET "\x1b[0m"
#define ANSI_BOLD "\x1b[1m"
#define ANSI_UNDERLINE "\x1b[4m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_RED "\x1b[31m"

extern volatile sig_atomic_t g_stop;
extern int					 g_pipefd[2];

#define SET(flags, flag) ((flags) |= (flag))
#define HAS(flags, flag) (((flags) & (flag)) != 0)

enum e_flags
{
	F_HELP = 1u << 0,
	F_IP_MODE = 1u << 1,
	F_FILE_MODE = 1u << 2,
	F_PORTS = 1u << 3,
	F_SCAN_TYPE = 1u << 4,
	F_SPEED = 1u << 5,
	F_SPOOF = 1u << 6
};

enum e_scan_type
{
	SCAN_SYN = 0,
	SCAN_NULL,
	SCAN_ACK,
	SCAN_FIN,
	SCAN_XMAS,
	SCAN_UDP
};

typedef struct s_args
{
	uint8_t flags;

	uint16_t ports[MAX_PORTS_COUNT];
	size_t	 port_count;

	uint8_t scan_type;
	uint8_t speed;
} t_args;

typedef struct s_target
{
	char			  *input;
	char			   ip[INET_ADDRSTRLEN];
	struct sockaddr_in addr;
} t_target;

typedef struct s_socket
{
	int				   sfd;
	int				   source_port;
	struct sockaddr_in sin;
} t_socket;

typedef struct s_ctx
{
	t_target *targets;
	size_t	  target_count;
	struct in_addr
		   my_ip; // probably not needed (if needed, use for pcap filter)
	char  *dev_name;
	t_args args;
} t_ctx;

typedef struct s_target_probe
{
	char	 ip[INET_ADDRSTRLEN];
	uint16_t port;

} t_target_probe;

typedef struct s_probe_request
{
	t_target_probe			target;
	enum e_scan_type		type;
	uint32_t				id;
	time_t					timestamp;
	uint8_t					retries;
	uint8_t					status;
	struct s_probe_request *next;
	struct s_probe_request *prev;
} t_probe_request;

typedef struct s_shared_data
{
	pcap_t		   *handle;
	pthread_mutex_t mutex;
	uint8_t			gateway_mac[ETH_ALEN]; // for ethernet header (bonus
										   // spoofing)
	t_probe_request *request_list_head;
	t_probe_request *request_list_tail;

} t_shared_data;

typedef struct s_ip_pseudo_hdr
{
	struct in_addr ip_src, ip_dst; /* source and dest address */
	uint8_t		   zero;
	uint8_t		   protocol;
	uint16_t	   tcp_length;
} t_ip_pseudo_hdr;

typedef struct s_pcap_user_data
{
	pcap_t *handle;
} t_pcap_user_data;

/* Type of packet SLL */

#define SLL_HOST 0x0000		 /* To us */
#define SLL_BROADCAST 0x0001 /* To all */
#define SLL_MULTICAST 0x0002 /* To group */
#define SLL_OTHERHOST 0x0003 /* To someone else */

struct sll_header // (SLL = "Linux cooked capture" or "Socket Linux Layer")
{
	uint16_t sll_pkt_type; // packet type (SLL_HOST, SLL_BROADCAST, etc.)
	uint16_t sll_hatype;   // link-layer address type (ARPHRD_ETHER, etc.)
	uint16_t sll_halen;	   // link-layer address length (e.g., 6 for Ethernet)
	uint8_t	 sll_addr[8];  // link-layer address (padded with zeros)
	uint16_t sll_protocol; // protocol (e.g., ETH_P_IP in network byte order)
};

// typedef struct s_ethernet_hdr
// {
// 	uint8_t	 dst_mac_addr[6];
// 	uint8_t	 src_mac_addr[6];
// 	uint16_t protocol;
// } t_ethernet_hdr;

/* Socket */
int	 init_socket(t_socket *sock);
void close_socket(t_socket socket);
void update_socket(struct sockaddr_in *socket, t_target target, uint16_t port);

/* Debug */
void print_ip_header(struct ip *ip_hdr);
// void print_eth_header(t_ethernet_hdr *eth_hdr);

/* TCP / IP */
void	 fill_pseudo_ip_header(t_ip_pseudo_hdr *ip_pseudo_hdr);
void	 fill_tcp_header(struct tcphdr *tcp_hdr);
uint16_t calculate_checksum(uint16_t *buffer, int len);
void	 calculate_tcp_checksum(t_ip_pseudo_hdr *ip_pseudo_hdr,
								struct tcphdr	*tcp_hdr);
void	 set_default_headers(char *buffer, t_ip_pseudo_hdr *ip_pseudo_hdr);
void	 print_tcp_header(struct tcphdr *tcp_hdr);
void	 print_ip_header(struct ip *ip_hdr);
void	 update_port_tcp(struct tcphdr *tcp_hdr, uint16_t port);
void	 update_ip_headers_dst_addr(t_ip_pseudo_hdr *ip_pseudo_hdr,
									struct in_addr	 dst_addr);

/* Scan */
bool  run_scan(t_ctx *ctx);
void *pcap_capture(void *arg);

/* Parsing */
bool parse_args(int argc, char **argv, t_args *args, char ***targets_input,
				size_t *target_count);
bool get_targets_input(const char *arg, size_t *args_count, char ***targets,
					   int mode, uint8_t flags);
bool resolve_targets(char **inputs, size_t count, t_target **out);
void free_targets(t_target **pt, size_t count);
void free_tabp(void ***ptab, size_t count);

/* Signal handlers */
bool setup_signal_handlers(void);

/* Pcap wrapper */
bool pcap_select_interface(char **dev_name, struct in_addr *my_ip);
int	 set_pcap_filter(pcap_t *interface);
bool pcap_setup(pcap_t **handle, const char *dev_name, struct in_addr my_ip,
				char *errbuf, t_target first_target_ip);

/* Decoding */
void decode_ip_packet(uint8_t *datagram, struct ip *ip_hdr);
// void decode_ethernet_packet(uint8_t *datagram, t_ethernet_hdr *eth_hdr);

void  handle_packet(u_char *args, const struct pcap_pkthdr *header,
					const u_char *packet);
void *send_packet(void *arg);

/* Debug print */
void print_debug_packet_start();
void print_debug_packet_end();
void print_debug_ethernet_header(struct ether_header *eth_header);
void print_debug_ip_header(struct ip *ip_hdr);
void print_debug_sll_header(struct sll_header *sll_hdr);
void print_debug_tcp_header(struct tcphdr *tcp_hdr);
void print_debug_udp_header(struct udphdr *udp_hdr);
void print_debug_icmp_header(struct icmphdr *icmp_hdr);
void print_debug_protocol(int protocol);
void print_debug_ethernet_type(int ether_type);
void print_debug_sll_protocol(int protocol);
void print_debug_datalink_type(int datalink_type);
void print_debug_parsing_args(t_ctx ctx);

#endif /* FT_NMAP_H */
