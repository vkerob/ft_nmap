#ifndef UTILS_H
#define UTILS_H

#include <stdbool.h>
#include "defines.h"
#include "typesdef.h"

bool substr(char *str, int start, int end, char **ptr);

u16 get_max_port_number(u16 ports[MAX_PORT_COUNT]);

#endif