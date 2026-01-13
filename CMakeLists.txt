cmake_minimum_required(VERSION 4.0)

project(ft_nmap
        VERSION 1.0
        LANGUAGES C)
include(CTest)

add_subdirectory(lib/libft)

file(GLOB_RECURSE SOURCES CONFIGURE_DEPENDS srcs/*.c)
file(GLOB_RECURSE TESTS CONFIGURE_DEPENDS "srcs/*.c" "tests/*.c")
list(REMOVE_ITEM TESTS ${CMAKE_CURRENT_SOURCE_DIR}/srcs/main.c)

add_executable(tests_ft_nmap ${TESTS})
add_executable(ft_nmap ${SOURCES})

set_target_properties(ft_nmap PROPERTIES
        RUNTIME_OUTPUT_NAME ft_nmap 
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}
)

set(INCLUDE_DIRS
        "${CMAKE_CURRENT_SOURCE_DIR}/includes"
        "${CMAKE_CURRENT_SOURCE_DIR}/lib/libft/includes"
)

target_include_directories(ft_nmap PRIVATE ${INCLUDE_DIRS})
target_include_directories(tests_ft_nmap PRIVATE ${INCLUDE_DIRS})

target_compile_options(ft_nmap PRIVATE
        -Wall -Wextra -Werror -g
)

target_compile_options(tests_ft_nmap PRIVATE
        -Wall -Wextra -Werror
)

find_path(PCAP_ROOT_DIR
    NAMES include/pcap.h
)

set (HINT_DIR ${PCAP_ROOT_DIR}/lib)

# message(${HINT_DIR})

#set(CMAKE_FIND_DEBUG_MODE TRUE)

find_library(LIBPCAP NAMES pcap HINTS ${HINTDIR} NO_CACHE REQUIRED NO_CMAKE_FIND_ROOT_PATH)

#set(CMAKE_FIND_DEBUG_MODE FALSE)

target_link_libraries(ft_nmap PRIVATE libft ${LIBPCAP})

target_link_libraries(tests_ft_nmap libft ${LIBPCAP})

foreach (TEST_SUITE ${TEST_SUITES})
    add_test(
            NAME "${TEST_SUITE}_suite"
            COMMAND tests_ft_nmap -s ${TEST_SUITE}
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
endforeach ()

enable_testing()