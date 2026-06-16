#include "commons.h"
#include "parsing.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FOPEN_READTEXT "r"

static char *trim_inplace(char *s)
{
	// trim left
	while (*s && isspace((unsigned char)*s))
		s++;

	// trim right (including trailing \n)
	size_t len = strlen(s);
	while (len > 0
		   && (s[len - 1] == '\n' || s[len - 1] == '\r'
			   || isspace((unsigned char)s[len - 1])))
	{
		s[--len] = '\0';
	}
	return s;
}

static int push_target(char ***targets, size_t *count, size_t *capacity,
					   const char *target)
{
	char **new_array;

	// ensure there is enough space
	if (*count >= *capacity)
	{
		// double the capacity (or start at 8)
		size_t new_capacity = (*capacity == 0) ? 8 : (*capacity * 2);

		new_array = realloc(*targets, new_capacity * sizeof(char *));
		if (new_array == NULL)
		{
			return FAILURE;
		}

		*targets = new_array;
		*capacity = new_capacity;
	}

	(*targets)[*count] = strdup(target);
	if ((*targets)[*count] == NULL)
	{
		return FAILURE;
	}

	(*count)++;

	return SUCCESS;
}

int get_targets_input(const char *arg, size_t *target_count, char ***targets,
					  int mode, u8 flags)
{
	if (HAS(flags, F_IP_MODE) && HAS(flags, F_FILE_MODE))
	{
		LOG("ft_nmap: cannot use --ip and --file options together\n");
		return FAILURE;
	}

	size_t count = 0, cap = 0;

	if (!arg || !target_count || !targets)
		return FAILURE;

	if (mode == IP_MODE)
	{
		// In case the user call --ip twice or --file followed by --ip
		if (*targets)
		{
			size_t i = 0;

			while (i < *target_count)
			{
				free((*targets)[i]);
				i++;
			}
			free(*targets);
		}
		*targets = malloc(sizeof(char *));
		if (!*targets)
		{
			return FAILURE;
		}
		(*targets)[0] = strdup(arg);
		if ((*targets)[0] == NULL)
		{
			free(*targets);
			*targets = NULL;
			return FAILURE;
		}

		*target_count = 1;
		return SUCCESS;
	}
	else if (mode == FILE_MODE)
	{
		FILE *file = fopen(arg, FOPEN_READTEXT);
		if (!file)
		{
			LOG("ft_nmap: Could not open file %s because %s\n", arg,
				strerror(errno));
			return FAILURE;
		}

		char line[1024];
		while (fgets(line, sizeof(line), file))
		{
			char *target = trim_inplace(line);

			if (*target == '\0' || *target == '#')
			{
				continue;
			}

			if (push_target(targets, &count, &cap, target) != 0)
			{
				fclose(file);
				return FAILURE;
			}
		}
		fclose(file);

		if (count == 0)
		{
			LOG("ft_nmap: No targets found in file %s\n", arg);
			return FAILURE;
		}

		// resize to fit exactly
		char **tmp = realloc(*targets, count * sizeof(char *));
		if (!tmp)
		{
			LOG("ft_nmap: memory allocation failed\n");
			return FAILURE;
		}

		*targets = tmp;
		*target_count = count;
		return SUCCESS;
	}

	return FAILURE;
}
