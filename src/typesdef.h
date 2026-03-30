#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <stdint.h>

typedef uint8_t				u8;
typedef uint16_t			u16;
typedef uint32_t			u32;
typedef struct ip			t_ip;
typedef struct tcphdr		t_tcp_hdr;
typedef struct udphdr		t_udp_hdr;
typedef struct ether_header t_eth_hdr;
#ifdef __APPLE__
typedef struct icmp t_icmp_hdr;
# define ICMP_CODE(hdr) ((hdr).icmp_code)
# define ICMP_TYPE(hdr) ((hdr).icmp_type)
#else
typedef struct icmphdr t_icmp_hdr;
# define ICMP_CODE(hdr) ((hdr).code)
# define ICMP_TYPE(hdr) ((hdr).type)
#endif
