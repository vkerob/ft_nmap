#include "greatest.h"
#include <signal.h>

GREATEST_MAIN_DEFS();
sig_atomic_t volatile g_stop = 0;
int main(const int argc, char **argv)
{
	GREATEST_MAIN_BEGIN(); /* command-line arguments, initialization. */
	GREATEST_MAIN_END();   /* display results */
}
