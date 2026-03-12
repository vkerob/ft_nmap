#include "tcp.h"

#include <stdatomic.h>
#include <string.h>

void update_port_tcp_header(struct tcphdr *tcp_hdr, u16 port)
{
	tcp_hdr->th_dport = htons(port);
}

static u8 scan_type_to_flag(t_scan_type scan_type)
{
	if (scan_type == SCAN_SYN)
	{
		return TH_SYN;
	}
	if (scan_type == SCAN_ACK)
	{
		return TH_ACK;
	}
	if (scan_type == SCAN_FIN)
	{
		return TH_FIN;
	}
	if (scan_type == SCAN_XMAS)
	{
		return TH_FIN | TH_URG | TH_PUSH;
	}
	// When scan type is NULL no bit are set in the TCP
	return 0x00;
}

void build_tcp_header(struct tcphdr *tcp_hdr, uint16_t destination_port,
					  const t_scan_type scan_type)
{
	memset(tcp_hdr, 0, sizeof(struct tcphdr));
	/* Source port */
	u16 src_port = get_random_source_port_in_scantype_interval(scan_type);
	// printf("SRC PORT: %hu\n", src_port);
	tcp_hdr->th_sport = htons(src_port);
	/* Destination port */
	tcp_hdr->th_dport = htons(destination_port);
	tcp_hdr->th_seq = 0;
	/* If ACK flag is set this is the value of the next sequence expected to
	 * receive */
	tcp_hdr->th_ack = htonl(0);
	tcp_hdr->th_x2 = 0;
	/* TCP Header length in 32 bit word */
	tcp_hdr->th_off = sizeof(*tcp_hdr) / 4;
	/* Control flags */
	tcp_hdr->th_flags = scan_type_to_flag(scan_type);
	/* Maximum size we can read in our buffer without windows scaling */
	tcp_hdr->th_win = htons(65535);
	/* Checksum */
	tcp_hdr->th_sum = 0;
	/* Set with URG flag to indicate the index where the urgent data is located*/
	tcp_hdr->th_urp = 0;
}
