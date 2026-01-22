#include "ft_nmap.h"
#include <pthread.h>

bool run_scan(t_ctx *ctx)
{
	pcap_t		  *handle;
	char		   errbuf[PCAP_ERRBUF_SIZE];
	const char	  *dev_name = ctx->dev_name;
	struct in_addr my_ip = ctx->my_ip;

	if (pcap_setup(&handle, dev_name, my_ip, errbuf))
		return true;

	// launch thread to handle captured packets
	

	// launch thread to send packets

	return false;
}