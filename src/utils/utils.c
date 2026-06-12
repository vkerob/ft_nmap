#include "utils.h"

#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

void better_free(void *ptr)
{
	if (ptr)
	{
		free(ptr);
	}
}

bool substr(char *str, int start, int end, char **ptr)
{
	int	  len = end - start;

	*ptr = calloc(len + 1, sizeof(char));
	if (*ptr == NULL)
	{
		LOG("ft_nmap: calloc failed: %s\n", strerror(errno));
		return true;
	}
	strncpy(*ptr, str + start, len);
	return false;
}

u16 get_max_port_number(u16 ports[MAX_PORT_COUNT])
{
	u16 max_port_val = 0;

	for (u16 i = 0; i < MAX_PORT_COUNT; i++)
	{
		if (ports[i] > max_port_val)
		{
			max_port_val = ports[i];
		}
	}
	return max_port_val;
}

