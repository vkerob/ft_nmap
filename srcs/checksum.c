
#include "ft_nmap.h"

uint16_t	calculate_checksum(char *buffer, int len)
{
	uint32_t	checksum = 0;
	uint16_t	*ptr = (uint16_t *)buffer;
	int				odd = (len % 2) != 0;

	for (int i = 0; i < len - odd; i++){
		checksum += *ptr;
		ptr++;
	}
	if (odd != 0)
	{
		uint8_t b = (uint8_t)*ptr;
		checksum += b;
	}
	checksum = (checksum >> 16) + (checksum & 0x0000FFFF);
	checksum += (checksum >> 16);


	return ((uint16_t)~checksum);
}

