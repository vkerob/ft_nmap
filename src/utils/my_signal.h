#ifndef MY_SIGNAL_H
#define MY_SIGNAL_H

#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>

extern volatile sig_atomic_t g_stop;
extern volatile sig_atomic_t g_display_output;

int setup_signal_handlers(void);

#endif
