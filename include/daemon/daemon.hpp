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

namespace AV {

class Daemon {

public:
    static int fd;
    static std::vector<pthread_t> threads;

    Daemon() = delete;

    static void Init();
    static void listen_socket();
    static void accept_connection();
private:
    static void hard_shutdown(int signum);
    static void soft_shutdown(int signum);
    static void *handle_connection(void* arg);
    static void close_fd(void* arg);
};

}
