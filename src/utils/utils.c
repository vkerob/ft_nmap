#include "utils.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int substr(const char *str, int start, int end, char **ptr)
{
	int len = end - start;

	*ptr = calloc(len + 1, sizeof(char));
	if (*ptr == NULL)
	{
		LOG("ft_nmap: calloc failed: %s\n", strerror(errno));
		return FAILURE;
	}
	strncpy(*ptr, str + start, len);
	return SUCCESS;
}

u16 get_max_port_number(const u16 ports[MAX_PORT_COUNT])
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
