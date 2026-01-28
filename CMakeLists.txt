cmake_minimum_required(VERSION 3.16)

project(baldo-scanner
  VERSION 0.1
  DESCRIPTION "Baldo malware scanner"
  LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

find_program(CCACHE_PROGRAM ccache) # use ccache if available
if (CCACHE_PROGRAM)
  message(STATUS "Using ccache: ${CCACHE_PROGRAM}")
  set(CMAKE_CXX_COMPILER_LAUNCHER "${CCACHE_PROGRAM}")
endif()

set(BALDO_COMPILE_OPTIONS -Wall -Wextra -Werror -Wpedantic)

#
# Daemon
#

set(BALDO_DAEMON_NAME baldo-daemon)
set(BALDO_DAEMON_LINK_LIBS pthread boost_program_options curl
  curlpp ssl crypto yara nl-3 nl-genl-3 seccomp)

file(GLOB BALDO_DAEMON_SOURCES "daemon/*.cpp" "daemon/*c" "common/*.cpp")

add_executable(${BALDO_DAEMON_NAME} ${BALDO_DAEMON_SOURCES})

target_include_directories(${BALDO_DAEMON_NAME} PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(${BALDO_DAEMON_NAME}
  ${BALDO_DAEMON_LINK_LIBS})

target_compile_options(${BALDO_DAEMON_NAME} PRIVATE
  ${BALDO_COMPILE_OPTIONS})

#
# Cli
#

set(BALDO_CLI_NAME baldo-cli)
set(BALDO_CLI_LINK_LIBS pthread boost_program_options)

file(GLOB BALDO_CLI_SOURCES "cli/*.cpp" "common/*.cpp" "daemon/*.c")

add_executable(${BALDO_CLI_NAME} ${BALDO_CLI_SOURCES})

target_include_directories(${BALDO_CLI_NAME} PUBLIC 
  ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(${BALDO_CLI_NAME}
  ${BALDO_CLI_LINK_LIBS})

target_compile_options(${BALDO_CLI_NAME} PRIVATE
  ${BALDO_COMPILE_OPTIONS})
