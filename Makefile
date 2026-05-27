# ft_nmap — Makefile wrapper around the CMake build.
#
# The real build system is CMake (see CMakeLists.txt). This Makefile is here
# to satisfy the subject ("you must submit a Makefile") and to provide the
# usual GNU make rules (all / clean / fclean / re). Behind the scenes it
# delegates to cmake, which already handles incremental recompilation.

NAME       := ft_nmap
BUILD_DIR  := build
CMAKE      ?= cmake
CMAKE_GEN_FLAGS ?=

.PHONY: all $(NAME) clean fclean re tests help

all: $(NAME)

# Configure (idempotent — cmake re-runs only when CMakeLists.txt changes)
# then build. CMake places the final ft_nmap binary at the project root via
# RUNTIME_OUTPUT_DIRECTORY, so no extra copy step is needed.
$(NAME):
	@$(CMAKE) -B $(BUILD_DIR) $(CMAKE_GEN_FLAGS)
	@$(CMAKE) --build $(BUILD_DIR) --target $(NAME)

# Build the test binary (greatest + pcre2). Requires root at runtime for
# the scan suite because it sends raw packets.
tests:
	@$(CMAKE) -B $(BUILD_DIR) $(CMAKE_GEN_FLAGS)
	@$(CMAKE) --build $(BUILD_DIR) --target tests_ft_nmap

clean:
	@$(RM) -r $(BUILD_DIR)

fclean: clean
	@$(RM) $(NAME)

re: fclean all

help:
	@echo "Targets:"
	@echo "  all / $(NAME)  Build the ft_nmap binary (default)"
	@echo "  tests          Build the unit-test binary tests_ft_nmap"
	@echo "  clean          Remove the build directory"
	@echo "  fclean         clean + remove the ft_nmap binary"
	@echo "  re             fclean + all"
