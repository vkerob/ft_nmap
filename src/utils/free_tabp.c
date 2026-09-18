#include "commons.h"

#include <stdlib.h>

void free_tabp(void ***ptab, size_t count)
{
	if (!ptab || !*ptab)
		return;
	for (size_t i = 0; i < count; i++)
		free((*ptab)[i]);
	free(*ptab);
	*ptab = NULL;
}
