#include "ft_nmap.h"

u16 calculate_checksum(void *buffer, int len)
{
	uint32_t	checksum = 0;
	u16			*ptr = (uint16_t *)buffer;
	int odd = (len % 2) != 0;

	while (len > odd)
	{
		checksum += *ptr++;
		len -= 2;
	}
	if (odd != 0)
	{
		u8 b = (u8)*ptr;
		checksum += b;
	}
	checksum = (checksum >> 16) + (checksum & 0x0000FFFF);
	checksum += (checksum >> 16);

	return (u16)~checksum;
}
