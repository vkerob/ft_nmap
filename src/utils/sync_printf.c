#include "commons.h"

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>

pthread_mutex_t printf_mutex = PTHREAD_MUTEX_INITIALIZER;

void sync_printf(const char *format, ...)
{
	va_list args;
	va_start(args, format);

	pthread_mutex_lock(&printf_mutex);
	vprintf(format, args);
	pthread_mutex_unlock(&printf_mutex);

	va_end(args);
}
