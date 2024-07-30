cmake_minimum_required(VERSION 3.29.2)
project("Antivirus")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

include_directories(include)

file(GLOB DAEMON_SOURCES "daemon/*.cpp" "daemon/**/*" "common/*.cpp")
file(GLOB CLI_SOURCES "cli/*.cpp" "common/*.cpp")

add_executable(daemon ${DAEMON_SOURCES})
add_executable(cli ${CLI_SOURCES})

# target_link_libraries(daemon pthread)
target_link_libraries(cli boost_program_options)

target_compile_options(daemon PRIVATE -Wall -pthread -lpthread)
target_compile_options(cli PRIVATE -Wall -pthread -lpthread)
