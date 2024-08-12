#pragma once

#include <string>
#include <vector>

#define STACK_SIZE (1024 * 1024)    /* Stack size for cloned child */

namespace AV
{

namespace Sandbox
{

/**
 * @brief Data about the sandbox
 */
struct app_data {
    std::string program_name;
    std::vector<std::string> arguments;
};

/**
 * @brief Parse the data from the sandbox
 *
 * @param data The data from the sandbox
 */
app_data parse_data(char* data);

/**
 * @brief Create a new thread to run
 *        the application in a sandbox
 *
 * @param data The data from the sandbox
 */
void run_threaded_sandbox(char* sandbox_data);

/**
 * @brief Run the application in a sandbox
 *
 * @param sandbox_data The data from the sandbox
 * Prints the pid of the applicationaits and
 * waits for the application to finish.
 */
void *thread_run_sandbox(void *data);

/**
 * @brief Run the application in a sandbox
 *
 * @param arg The data from the sandbox
 */
static int sandboxed_process(void* arg);

/**
 * @brief Print the app_data struct
 *
 * @param data The data to print
 */
void print_data(struct Sandbox::app_data data);

} // namespace Sandbox

} // namespace AV
