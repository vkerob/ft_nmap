#include <libft.h>

#include "greatest.h"

extern SUITE(strlen_suite);

extern SUITE(atoi_suite);

extern SUITE(memset_suite);

extern SUITE(isspace_suite);

extern SUITE(isdigit_suite);

GREATEST_MAIN_DEFS();

int main(const int argc, char **argv) {
	GREATEST_MAIN_BEGIN(); /* command-line arguments, initialization. */

	RUN_SUITE(strlen_suite);
	RUN_SUITE(atoi_suite);
	RUN_SUITE(memset_suite);

	GREATEST_MAIN_END(); /* display results */
}
