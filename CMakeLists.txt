cmake_minimum_required(VERSION 3.12)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

project(ft_nmap
        VERSION 1.0
        LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
include(CTest)

add_subdirectory(lib/pcre2-10.47)

option(FT_NMAP_SANITIZERS "Enable ASAN/UBSAN in Debug builds" ON)
set(FT_NMAP_SANITIZER_COMPILE_FLAGS)
set(FT_NMAP_SANITIZER_LINK_FLAGS)
if(FT_NMAP_SANITIZERS)
        include(CheckCSourceCompiles)
        set(CMAKE_REQUIRED_FLAGS "-fsanitize=address,undefined")
        check_c_source_compiles("int main(void) { return 0; }" FT_NMAP_HAVE_SANITIZERS)
        unset(CMAKE_REQUIRED_FLAGS)

        if(FT_NMAP_HAVE_SANITIZERS)
                list(APPEND FT_NMAP_SANITIZER_COMPILE_FLAGS -fsanitize=address,undefined -fno-omit-frame-pointer)
                list(APPEND FT_NMAP_SANITIZER_LINK_FLAGS -fsanitize=address,undefined)
        else()
                message(WARNING
                        "FT_NMAP_SANITIZERS=ON but this toolchain has no ASAN/UBSAN runtime "
                        "(libasan/libubsan missing). Building without sanitizers.")
        endif()
endif()

file(GLOB_RECURSE SOURCES CONFIGURE_DEPENDS src/*.c)
file(GLOB_RECURSE TESTS CONFIGURE_DEPENDS "src/**/*.c" "tests/*.c")
list(REMOVE_ITEM TESTS ${CMAKE_CURRENT_SOURCE_DIR}/src/main.c)

add_executable(tests_ft_nmap ${TESTS})
add_executable(ft_nmap ${SOURCES})

set_target_properties(ft_nmap PROPERTIES
        RUNTIME_OUTPUT_NAME ft_nmap
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}
)

file(GLOB_RECURSE HEADER_FILES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/src/*.h")
set(INCLUDE_DIRS)
foreach(_h ${HEADER_FILES})
        get_filename_component(_dir ${_h} DIRECTORY)
        list(APPEND INCLUDE_DIRS ${_dir})
endforeach()
list(REMOVE_DUPLICATES INCLUDE_DIRS)

target_compile_options(ft_nmap PRIVATE
        -Wall -Wextra -Werror -g
        ${FT_NMAP_SANITIZER_COMPILE_FLAGS}
)

target_compile_options(tests_ft_nmap PRIVATE
        -Wall -Wextra -Werror -g
        ${FT_NMAP_SANITIZER_COMPILE_FLAGS}
)

target_link_options(ft_nmap PRIVATE
        ${FT_NMAP_SANITIZER_LINK_FLAGS}
)

target_link_options(tests_ft_nmap PRIVATE
        ${FT_NMAP_SANITIZER_LINK_FLAGS}
)

find_path(PCAP_ROOT_DIR
    NAMES include/pcap.h
)

set (HINT_DIR ${PCAP_ROOT_DIR}/lib)


set(HINT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/lib/pcre2-10.47/build/)

find_library(LIBPCAP NAMES pcap HINTS ${HINT_DIR} REQUIRED NO_CMAKE_FIND_ROOT_PATH)


list(APPEND INCLUDE_DIRS ${PCRE2_HEADER_DIR})


target_include_directories(ft_nmap PRIVATE ${INCLUDE_DIRS})
target_include_directories(tests_ft_nmap PRIVATE ${INCLUDE_DIRS})


target_link_libraries(ft_nmap PRIVATE ${LIBPCAP})

target_link_libraries(tests_ft_nmap ${LIBPCAP} pcre2-8)

list(APPEND TEST_SUITES parsing scan)

foreach (TEST_SUITE ${TEST_SUITES})
    add_test(
            NAME "${TEST_SUITE}_suite"
            COMMAND tests_ft_nmap -s ${TEST_SUITE}
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
endforeach ()

enable_testing()
