#ifndef MY_SIGNAL_H
#define MY_SIGNAL_H

#include <stdatomic.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdlib.h>

extern volatile sig_atomic_t	g_stop;

bool	setup_signal_handlers(void);

#endif
