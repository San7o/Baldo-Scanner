cmake_minimum_required(VERSION 3.29.2)
project("Antivirus" VERSION 0.1)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})


# daemon ---------------------------------------------

file(GLOB DAEMON_SOURCES "daemon/*.cpp" "daemon/**/*" "common/*.cpp")

add_executable(daemon ${DAEMON_SOURCES})

target_include_directories(daemon PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include )

target_link_libraries(daemon pthread boost_program_options curl curlpp ssl crypto yara)

target_compile_options(daemon PRIVATE -Wall)


# cli ------------------------------------------------

file(GLOB CLI_SOURCES "cli/*.cpp" "common/*.cpp")

add_executable(cli ${CLI_SOURCES})

target_include_directories(cli PUBLIC 
        ${CMAKE_CURRENT_SOURCE_DIR}/include )

target_link_libraries(cli pthread boost_program_options)

target_compile_options(cli PRIVATE -Wall)
