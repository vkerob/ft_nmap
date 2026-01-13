
#include "ft_nmap.h"

uint16_t	calculate_checksum(char *buffer, int len)
{
	uint32_t	checksum = 0;
	uint16_t	*ptr = (uint16_t *)buffer;

	for (int i = 0; i < len; i++){
		checksum += *ptr;
		ptr++;
	}
	checksum = (checksum >> 16) && (checksum & 0x0000FFFF);
	checksum += (checksum >> 16);
	return ~checksum;
}
