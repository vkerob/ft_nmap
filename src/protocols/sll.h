
#ifndef SLL_H
#define SLL_H

#include "typesdef.h"

/* Type of packet SLL */

#define SLL_HOST 0x0000		 /* To us */
#define SLL_BROADCAST 0x0001 /* To all */
#define SLL_MULTICAST 0x0002 /* To group */
#define SLL_OTHERHOST 0x0003 /* To someone else */

typedef struct	s_sll_hdr // (SLL = "Linux cooked capture" or "Socket Linux Layer")
{
	u16	sll_pkt_type;	// packet type (SLL_HOST, SLL_BROADCAST, etc.)
	u16	sll_hatype;		// link-layer address type (ARPHRD_ETHER, etc.)
	u16	sll_halen;		// link-layer address length (e.g., 6 for Ethernet)
	u8	sll_addr[8];	// link-layer address (padded with zeros)
	u16	sll_protocol;	// protocol (e.g., ETH_P_IP in network byte order)
}	t_sll_hdr;

void	print_debug_sll_protocol(int protocol);
void	print_debug_sll_header(t_sll_hdr *sll_hdr);

#endif
