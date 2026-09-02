#ifndef TRACEROUTE_H
#define TRACEROUTE_H

/* scan.h expects struct timeval and pthread_mutex_t to be already declared. */
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <sys/time.h>

#include "defines.h"
#include "scan.h"
#include "typesdef.h"

/* Probe geometry */
#define TRACE_BASE_PORT 33434
#define TRACE_DEFAULT_MAX_HOPS 30
#define TRACE_MAX_HOPS 255
#define TRACE_DEFAULT_NQUERIES 3
#define TRACE_MAX_NQUERIES 10
#define TRACE_DEFAULT_PACKETLEN 60
#define TRACE_PACKET_LEN_MIN 28
#define TRACE_PACKET_LEN_MAX 65000
#define TRACE_IP_HEADER_LEN 20

/* Slack on the hop count estimated from the target's reply TTL, which
 * assumes a standard initial TTL and a symmetric path. */
#define TRACE_TTL_MARGIN 2

/* Per-probe reply timeout */
#define TRACE_PROBE_TIMEOUT_US 300000

/* trace_receive_reply: no answer before the timeout (distinct from FAILURE,
 * which means the trace itself cannot continue) */
#define TRACE_NO_REPLY 1

#ifdef __APPLE__
#define TRACE_ICMP_TIME_EXCEEDED ICMP_TIMXCEED
#define TRACE_ICMP_DEST_UNREACH ICMP_UNREACH
#define TRACE_ICMP_PORT_UNREACH ICMP_UNREACH_PORT
#else
#define TRACE_ICMP_TIME_EXCEEDED ICMP_TIME_EXCEEDED
#define TRACE_ICMP_DEST_UNREACH ICMP_DEST_UNREACH
#define TRACE_ICMP_PORT_UNREACH ICMP_PORT_UNREACH
#endif

/* Probe kinds. Setting both probes each hop with a UDP datagram and an ICMP
 * echo, and the first answer wins. */
enum e_trace_flags
{
	F_TR_UDP = 1u << 0,
	F_TR_ICMP = 1u << 1
};

typedef enum e_trace_mode
{
	TRACE_MODE_UDP,
	TRACE_MODE_ICMP,
	TRACE_MODE_BOTH
} t_trace_mode;

typedef struct s_trace_opts
{
	u8	flags;
	int packetlen;
	int max_hops;
	int nqueries;
} t_trace_opts;

typedef struct s_trace_ctx
{
	/* UDP send socket, -1 when the mode does not send UDP probes. */
	int sock_udp;
	/* Raw ICMP socket, open in every mode: it receives every answer, and it
	 * sends the echo probes when the mode uses them. */
	int				   sock_icmp;
	struct sockaddr_in dst;
	t_trace_mode	   mode;
	u16				   echo_id;
} t_trace_ctx;

/* A single probe answer, as decoded from the wire */
typedef struct s_trace_reply
{
	struct sockaddr_in addr;
	double			   rtt_ms;
	u8				   icmp_type;
	u8				   icmp_code;
	bool			   reached_dst;
} t_trace_reply;

typedef struct s_hop_reply
{
	struct in_addr addr;
	double		   rtt_ms;
	bool		   received;
} t_hop_reply;

/* Answers collected for one TTL. A hop can be answered by several routers
 * (load balancing), so each probe keeps its own source address. */
typedef struct s_hop
{
	t_hop_reply replies[TRACE_MAX_NQUERIES];
	u8			nb_probes;
	bool		reached_dst;
} t_hop;

/* traceroute.c */
void		 trace_opts_init(t_trace_opts *opts);
t_trace_mode trace_mode_from_flags(u8 flags);

/* Trace the route to target. `hops` must hold at least opts->max_hops
 * entries; `hop_count` receives the number actually filled. Fills the
 * structure, prints nothing. */
int trace_route(const t_target *target, const t_trace_opts *opts, t_hop *hops,
				u8 *hop_count);

/* print_traceroute.c — runs the trace and prints it nmap-style. Must be
 * called after the scan threads are joined. */
void print_traceroute(const t_target *target, const t_trace_opts *opts);

/* trace_socket.c */
int	 trace_init_sockets(t_trace_ctx *ctx, const t_trace_opts *opts);
void trace_close_sockets(t_trace_ctx *ctx);

/* trace_probe.c */
int trace_send_probe(t_trace_ctx *ctx, const t_trace_opts *opts, int ttl,
					 int probe, struct timeval *start);
int trace_receive_reply(t_trace_ctx *ctx, const t_trace_opts *opts, int ttl,
						int probe, t_trace_reply *reply, struct timeval *start);

#endif
