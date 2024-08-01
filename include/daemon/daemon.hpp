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

namespace AV
{

class Daemon
{
public:
    static const int MAX_THREADS;
    static const std::string version;

    static int fd;
    static int fd_kernel;
    static int available_threads;
    static bool stop;
    static std::vector<pthread_t> threads;
    static std::mutex threads_mutex;
    static std::mutex available_threads_mutex;

    Daemon() = delete;

    static void Init();
    static void listen_socket();
    static void listen_kernel();
    static void graceful_shutdown();
private:
    static void hard_shutdown(int signum);
    static void set_graceful_shutdown(int signum);
    static void *thread_handle_connection(void* arg);
    static void *thread_listen_kernel(void* arg);
    static void *thread_scan(void* arg);
    static void close_fd(void* arg);
    static void free_request(void* arg);
    static void print_settings(Settings settings);
    static void parse_settings(Settings settings, int fd);
    static void scan_files(std::string scanFile,
                    Enums::ScanType scanType, bool multithread);
    static void produce_report(ScanReport* report);
};

}
