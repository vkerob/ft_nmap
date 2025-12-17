#include "ft_nmap.h"
#include "parsing.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
			return -1;

		*targets = new_array;
		*capacity = new_capacity;
	}

	(*targets)[*count] = strdup(target);
	if ((*targets)[*count] == NULL)
		return -1;

	(*count)++;

	return 0;
}

static void free_targets_input(char **targets, size_t count)
{
	if (!targets)
		return;
	for (size_t i = 0; i < count; i++)
		free(targets[i]);
	free(targets);
}

char **get_targets_input(const char *arg, size_t *args_count, int mode)
{
	char **targets = NULL;
	size_t count = 0, cap = 0;

	*args_count = 0;

	if (mode == IP_MODE)
	{
		targets = malloc(sizeof(char *));
		if (!targets)
			return NULL;
		targets[0] = strdup(arg);
		if (!targets[0])
		{
			free(targets);
			return NULL;
		}
		*args_count = 1;

		return targets;
	}
	else if (mode == FILE_MODE)
	{
		FILE *file = fopen(arg, "r");
		if (!file)
		{
			fprintf(stderr, "ft_nmap: Could not open file %s\n", arg);
			return NULL;
		}

		char line[1024];
		while (fgets(line, sizeof(line), file))
		{
			char *target = trim_inplace(line);

			if (*target == '\0')
				continue;
			if (*target == '#')
				continue;

			if (push_target(&targets, &count, &cap, target) != 0)
			{
				fclose(file);
				free_targets_input(targets, count);
				return NULL;
			}
		}

		fclose(file);

		if (count == 0)
		{
			fprintf(stderr, "ft_nmap: No targets found in file %s\n", arg);
			free_targets_input(targets, count);
			return NULL;
		}

		// resize to fit exactly
		char **tmp;
		tmp = realloc(targets, count * sizeof(char *));
		if (tmp == NULL)
		{
			fprintf(stderr, "ft_nmap: memory allocation failed\n");
			free_targets_input(targets, count);
			return NULL;
		}
		targets = tmp;
		*args_count = count;

		return targets;
	}

	return NULL;
}
