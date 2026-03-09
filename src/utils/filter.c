#include "setup.h"

#include <stdio.h>
#include <stdlib.h>

int	set_pcap_filter(pcap_t *interface)
{
	struct bpf_program	filter_program;

	if (pcap_compile(
			interface,
			&filter_program,
			// "src host 192.168.64.11",
			"tcp",
			1,
			PCAP_NETMASK_UNKNOWN) < 0)
	{
		fprintf(stderr, "pcap_compile: %s\n", pcap_geterr(interface));
		return EXIT_FAILURE;
	}
	if (pcap_setfilter(interface, &filter_program) < 0)
	{
		fprintf(stderr, "pcap_set_filter: %s\n", pcap_geterr(interface));
		return EXIT_FAILURE;
	}
	pcap_freecode(&filter_program);
	return EXIT_SUCCESS;
}
