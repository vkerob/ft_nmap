cmake_minimum_required(VERSION 3.5...3.26)

project(libft
				VERSION 1.0
				LANGUAGES C)
include(CTest)
file(GLOB_RECURSE SOURCES CONFIGURE_DEPENDS srcs/*.c)

add_library(libft ${SOURCES})

set_target_properties(libft PROPERTIES
	RUNTIME_OUTPUT_NAME libft
	RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}
)

target_include_directories(libft PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/includes")

target_compile_options(libft PRIVATE
	-Wall -Wextra -Werror
)

file(GLOB_RECURSE TESTS CONFIGURE_DEPENDS tests/*.c)

add_executable(tests_libft ${TESTS})

target_compile_options(tests_libft PRIVATE
	-Wall -Wextra -Werror
)
target_link_libraries(tests_libft libft)

add_test(
	NAME "tests_libft"
	COMMAND tests_libft)

enable_testing()
