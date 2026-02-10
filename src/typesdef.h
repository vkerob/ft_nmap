#include <stdint.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>

typedef uint8_t							u8;
typedef uint16_t						u16;
typedef uint32_t						u32;
typedef struct ip						t_ip;
typedef struct tcphdr				t_tcp_hdr;
typedef struct udphdr				t_udp_hdr;
typedef struct ether_header	t_eth_hdr;
