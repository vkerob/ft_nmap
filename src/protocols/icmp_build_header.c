#include "icmp.h"

void build_icmp_header(t_icmp_hdr *icmp_hdr, uint16_t destination_port,
					  const t_scan_type scan_type)
{
	memset(icmp_hdr, 0, sizeof(t_icmp_hdr));

  
  icmp_hdr->icmp_type = ICMP_ECHO;
	icmp_hdr->icmp_code = 0;
	icmp_hdr->icmp_id = htons(getpid());
	icmp_hdr->icmp_seq = htons(1);
	icmp_hdr->icmp_cksum = 0;



	/* Source port */
	// u16 src_port = get_random_source_port_in_scantype_interval(scan_type);
	// tcp_hdr->th_sport = htons(src_port);
	// /* Destination port */
	// tcp_hdr->th_dport = htons(destination_port);
	// tcp_hdr->th_seq = 0;
	// /* If ACK flag is set this is the value of the next sequence expected to
	//  * receive */
	// tcp_hdr->th_ack = htonl(0);
	// tcp_hdr->th_x2 = 0;
	// /* TCP Header length in 32 bit word */
	// tcp_hdr->th_off = sizeof(*tcp_hdr) / 4;
	// /* Control flags */
	// tcp_hdr->th_flags = scan_type_to_flag(scan_type);
	// /* Maximum size we can read in our buffer without windows scaling */
	// tcp_hdr->th_win = htons(65535);
	// /* Checksum */
	// tcp_hdr->th_sum = 0;
	// /* Set with URG flag to indicate the index where the urgent data is located*/
	// tcp_hdr->th_urp = 0;
}
