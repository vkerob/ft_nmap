#include "tcp.h"

#include <stdatomic.h>
#include <string.h>

void	update_port_tcp_header(struct tcphdr *tcp_hdr, u16 port)
{
	tcp_hdr->th_dport = htons(port);
}

void build_tcp_header(
	struct tcphdr *tcp_hdr,
	uint16_t destination_port,
	_Atomic uint16_t *base_port)
{
	memset(tcp_hdr, 0, sizeof(struct tcphdr));
	/* Source port */
	tcp_hdr->th_sport = htons(atomic_load(base_port));
	/* Destination port */
	tcp_hdr->th_dport = htons(destination_port);
	tcp_hdr->th_seq = 0;
	/* If ACK flag is set this is the value of the next sequence expected to receive */
	tcp_hdr->th_ack = htonl(0);
	tcp_hdr->th_x2 = 0;
	/* TCP Header length in 32 bit word */
	tcp_hdr->th_off = sizeof(*tcp_hdr) / 4;
	/* Control flags */
	tcp_hdr->th_flags = TH_SYN;
	/* Maximum size we can read in our buffer without windows scaling */
	tcp_hdr->th_win = htons(65535);
	/* Checksum */
	tcp_hdr->th_sum = 0;
	/* Set with URG flag to indicate the index where the urgent data is located */
	tcp_hdr->th_urp = 0;
}
