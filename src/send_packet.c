#include "ft_nmap.h"
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>

#define IP_VERSION 4
#define IP_IHL 5
#define IP_TTL_DEFAULT 64

// bonus: for later
// note: build with a spoofed src and dst gateway MAC address
void build_ethernet_header(struct ether_header *eth_hdr)
{
	(void)eth_hdr;
	eth_hdr->ether_type = htons(ETHERTYPE_IP);
}

void build_ip_header(struct ip *ip_hdr, t_probe_request *request,
					 char *source_ip, _Atomic uint16_t *id_counter)
{
	(void)ip_hdr;
	(void)request;
	ip_hdr->ip_v = IP_VERSION;
	ip_hdr->ip_hl = IP_IHL;
	ip_hdr->ip_ttl = IP_TTL_DEFAULT;
	ip_hdr->ip_p = (request->type == SCAN_UDP) ? IPPROTO_UDP : IPPROTO_TCP;
	ip_hdr->ip_len = htons(sizeof(struct ip));

	// for ip_off htons(0x4000) sets the DF (Don't Fragment) flag but it's
	// poossible to be rejected by some firewalls
	ip_hdr->ip_off = 0;
	ip_hdr->ip_id = htons(atomic_fetch_add(id_counter, 1));
	// ip_hdr->ip_sum = calculate_checksum(ip_hdr, ip_hdr->ip_hl * 4);
	ip_hdr->ip_src.s_addr = inet_addr(source_ip);
	ip_hdr->ip_dst.s_addr = inet_addr(request->target.ip);
	// no priority
	ip_hdr->ip_tos = 0;
}

void build_tcp_header(
	struct tcphdr *tcp_hdr,
	uint16_t destination_port,
	_Atomic uint16_t *base_port)
{
	// Will be use to calculate the TCP checksum
	memset(tcp_hdr, 0, sizeof(struct tcphdr));
	/* Source port */
	printf("base port: %d\n", *base_port);
	tcp_hdr->th_sport = htons(*base_port);
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

void build_udp_header(struct udphdr *udp_hdr, uint16_t dest_port)
{
	(void)udp_hdr;
	(void)dest_port;
}

void assemble_full_packet(u_char *packet, struct ether_header *eth_hdr,
						  struct ip *ip_hdr, struct tcphdr *tcp_hdr,
						  struct udphdr *udp_hdr)
{
	(void)packet;
	(void)eth_hdr;
	(void)ip_hdr;
	(void)tcp_hdr;
	(void)udp_hdr;
}

static void build_scan_packets(t_probe_request *request, u_char *packet,
							   t_shared_data *shared_data)
{
	// struct ether_header	eth_hdr;
	t_ip_pseudo_hdr		ip_pseudo_hdr;
	// struct ip			ip_hdr;
	struct tcphdr		tcp_hdr;
	struct udphdr		udp_hdr;

	memset(&tcp_hdr, 0, sizeof(tcp_hdr));
	memset(&udp_hdr, 0, sizeof(udp_hdr));
	memset(&ip_pseudo_hdr, 0, sizeof(ip_pseudo_hdr));

	// if (shared_data->gateway_mac[0] != 0)
		// build_ethernet_header(&eth_hdr);

	// build_ip_header(&ip_hdr, request, shared_data->source_ip, &shared_data->id);

	// Use to compute the tcp checksum
	build_pseudo_ip_header(&ip_pseudo_hdr);

	if (request->type == SCAN_SYN || request->type == SCAN_ACK
		|| request->type == SCAN_FIN || request->type == SCAN_XMAS
		|| request->type == SCAN_NULL)
	{
		// assemble full packet
		build_tcp_header(&tcp_hdr, request->target.port,
						 &shared_data->base_port);
		calculate_tcp_checksum(&ip_pseudo_hdr, &tcp_hdr);
	}
	else if (request->type == SCAN_UDP)
	{
		// build UDP header
		build_udp_header(&udp_hdr, request->target.port);
	}
	//TEMPORARY

	memcpy(packet, &tcp_hdr, sizeof(tcp_hdr));
	(void)packet;
	// assemble_full_packet(packet, &eth_hdr, &ip_hdr, &tcp_hdr, &udp_hdr);
}

static bool send_packet(t_socket *socket, u8 *packet)
{
	if (sendto(
			socket->sfd,
			packet,
			sizeof(struct tcphdr),
			0,
			(struct sockaddr *)&socket->sin,
			sizeof(struct sockaddr)
		) < 0)
	{
		perror("sendto: ");
		return false;
	}
	return true;
}

void *send_routine(void *arg)
{
	t_shared_data	*shared_data = (t_shared_data *)arg;
	u8				packet[4096];
	t_socket		socket;
	t_probe_request	*popped_request = NULL;

	//TODO: remove after debug

	init_socket(&socket);
	memset(packet, 0, sizeof(packet));
	socket.sin.sin_family = AF_INET;
	while (shared_data->nb_probe_requests > 0)
	{
		pthread_mutex_lock(&shared_data->mutex);
		if (shared_data->request_list_tail){
			pop_probe_request(&shared_data->request_list_head, shared_data->request_list_tail, &popped_request);
		}
		else{
			return NULL;
		}
		shared_data->nb_probe_requests--;
		pthread_mutex_unlock(&shared_data->mutex);
		inet_aton(popped_request->target.ip, &socket.sin.sin_addr);
		build_scan_packets(popped_request, packet, shared_data);

		socket.sin.sin_port = popped_request->target.port;
		// printf("port: %d | target ip: %s\n",popped_request->target.port, popped_request->target.ip );

		if (!send_packet(&socket, packet)){
			//TODO: handle this case
			return NULL;
		}

		free(popped_request);
	}
	return NULL;
}
