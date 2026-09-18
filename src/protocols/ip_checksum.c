#include "ip.h"
#include "typesdef.h"

u16 calculate_checksum(const void *buffer, int len)
{
	uint32_t   checksum = 0;
	const u16 *ptr = (const uint16_t *)buffer;
	int		   odd = (len % 2) != 0;

	while (len > odd)
	{
		checksum += *ptr++;
		len -= 2;
	}
	if (odd != 0)
	{
		/* Only one byte left: read it as a byte to avoid a 2-byte over-read. */
		u8 b = *(const u8 *)ptr;
		checksum += b;
	}
	checksum = (checksum >> 16) + (checksum & 0x0000FFFF);
	checksum += (checksum >> 16);

	return (u16)~checksum;
}
