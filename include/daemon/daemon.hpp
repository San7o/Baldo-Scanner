#pragma once

#define SOCK_PATH "/tmp/av1"
#define VERSION "1.0"
#define PROGRAM_PATH "/etc/antivirus/"
#define RULES_PATH "/etc/antivirus/compiled_rules.yar"
#define DB_PATH "/etc/antivirus/signatures.db"

#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <cerrno>
#include <stdio.h>
#include <vector>
#include <pthread.h>
#include <unistd.h>
#include <signal.h>
#include <filesystem>
#include <mutex>

#include "common/settings.hpp"
#include "daemon/engine.hpp"

#include <netlink/netlink.h>

namespace AV
{

/**
 * @brief Daemon singleton class
 *
 * ## Description
 * This singleton static class is responsible for the main daemon logic.
 * It initializes the daemon by creating a new directory in /etc/antivirus
 * and setting up signal handlers and yaralib. It handles the listening
 * on two different sockets, one for the client (cli tool) and one for the
 * kernel module. The cli tool is used to send messaes to the daemon, 
 * multiple clients can connect to the daemon at the same time as the daemon
 * will spawn one thread per connection. The kernel module is used to send
 * scan requests to the daemon and are recieved by a single socket.
 *
 * ## Threads
 * All the threads spawned by the daemon are tracked by the `threads`
 * vector so that they can be exited or waited later. For each connection
 * and for each scan, a new thread is created. The threads for scanning
 * are stored in a different vector, `scan_threads`, and they cannot be
 * accessed globally, as they are only used to wait for the threads to
 * finish before compleating the scan.
 *
 * ## Shutdown
 * The daemon can be stopped by sending a SIGINT signal, which will
 * trigger a graceful shutdown which will wait for all the threads to
 * finish before exiting. The daemon can also be stopped by sending a
 * SIGTERM or SIGQUIT signal, which will trigger a hard shutdown, exiting
 * forcefully,ì without waiting for the threads to finish.
 */
class Daemon
{

public:

/*
 * The MAX_THREADS constant is used to limit the number of threads that
 * can be spowned for scanning. This is done to prevent the system from
 * running out of resources. The value is initialized to
 * `std::thread::hardware_concurrency()` which returns the optimal number
 * of threads that can be run concurrently on the system.
 */
static const int MAX_THREADS;
/* The version of the daemon, defined in VERSION */
static const std::string version;

static int  fd;
static int  available_threads;
static bool stop;
static std::vector<pthread_t> threads;
static std::mutex threads_mutex;
static std::mutex available_threads_mutex;

Daemon() = delete;

/* Methods */

static void Init();
static void listen_socket();
static void graceful_shutdown();
static void hard_shutdown(int signum);

private:
static void set_graceful_shutdown(int signum);
/* thread functions */
static void *thread_handle_connection(void* arg);
static void *thread_scan(void* arg);
/* free functions */
static void close_fd(void* arg);
static void free_request(void* arg);
/* Printing */
static void print_settings(Settings settings);
static void parse_settings(Settings settings, int fd);
static void scan_files(std::string scanFile,
            Enums::ScanType scanType, bool multithread);
static void produce_report(ScanReport* report);
};

}
