#pragma once

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

#define SOCK_PATH "/tmp/av1"
#define VERSION "1.0"

namespace AV {

class Daemon {

public:
    static int fd;
    static std::vector<pthread_t> threads;
    static bool shutdown;
    static std::string version;

    Daemon() = delete;

    static void Init();
    static void listen_socket();
    static void graceful_shutdown();
private:
    static void hard_shutdown(int signum);
    static void set_graceful_shutdown(int signum);
    static void *handle_connection(void* arg);
    static void close_fd(void* arg);
};

}
