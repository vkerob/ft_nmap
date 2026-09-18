#ifndef UTILS_H
#define UTILS_H

#include "defines.h"
#include "typesdef.h"
#include <stdbool.h>

int substr(const char *str, int start, int end, char **ptr);

u16 get_max_port_number(const u16 ports[MAX_PORT_COUNT]);

#endif