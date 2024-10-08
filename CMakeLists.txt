cmake_minimum_required(VERSION 3.29.2)
project("Antivirus" VERSION 0.1)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})


# ================ daemon ================

file(GLOB DAEMON_SOURCES "daemon/*.cpp" "daemon/*c" "common/*.cpp")

add_executable(av_daemon ${DAEMON_SOURCES})

target_include_directories(av_daemon PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include )

target_link_libraries(av_daemon pthread boost_program_options
        curl curlpp ssl crypto yara nl-3 nl-genl-3 seccomp)

target_compile_options(av_daemon PRIVATE -Wall)


# ================ cli ================

file(GLOB CLI_SOURCES "cli/*.cpp" "common/*.cpp" "daemon/*.c")

add_executable(cli ${CLI_SOURCES})

target_include_directories(cli PUBLIC 
        ${CMAKE_CURRENT_SOURCE_DIR}/include )

target_link_libraries(cli pthread boost_program_options)

target_compile_options(cli PRIVATE -Wall)
