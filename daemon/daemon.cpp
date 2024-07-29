#include "daemon/daemon.hpp"
#include "common/logger.hpp"
#include <unistd.h>

using namespace AV;

int Daemon::fd;
std::vector<pthread_t> Daemon::threads = {};
bool Daemon::shutdown = false;

void Daemon::Init()
{
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == -1)
    {
        perror("socket");
        exit(1);
    }

    if (std::filesystem::exists(SOCK_PATH))
    {
        std::filesystem::remove(SOCK_PATH);
    }
    
    struct sockaddr_un addr;
    addr.sun_family = AF_UNIX;
    if (strcpy(addr.sun_path, SOCK_PATH) == NULL)
    {
        perror("strcpy");
        exit(1);
    }

    if (bind(fd, (struct sockaddr*) &addr, sizeof(addr)) == -1)
    {
        perror("bind");
        exit(1);
    }

    struct sigaction sa;
    sa.sa_handler = set_graceful_shutdown;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);    // graceful shutdown

    struct sigaction sterm;
    sterm.sa_handler = hard_shutdown;
    sterm.sa_flags = 0;
    sigemptyset(&sterm.sa_mask);
    if (sigaction(SIGTERM, &sterm, NULL) == -1) // hard shutdown
    {
        perror("sigaction");
        exit(1);
    }
    if (sigaction(SIGQUIT, &sterm, NULL) == -1) // hard shutdown
    {
        perror("sigaction");
        exit(1);
    }
}

void Daemon::listen_socket()
{
    if (listen(fd, 5) == -1)
    {
        perror("listen");
        exit(1);
    }
    int new_fd = accept(fd, NULL, NULL);
    if (new_fd == -1)
    {
        perror("accept");
    }

    pthread_t thread;
    pthread_attr_t attr;
    if (pthread_attr_init(&attr) != 0)
    {
        perror("pthread_attr_init");
        exit(1);
    }

    if (!Daemon::shutdown) {
        if (pthread_create(&thread, &attr, handle_connection, &new_fd) != 0)
        {
            perror("pthread_create");
            exit(1);
        }
        threads.push_back(thread);

        if (pthread_attr_destroy(&attr))
        {
            perror("pthread_attr_destroy");
            exit(1);
        }
    }
}

void Daemon::hard_shutdown(int signum)
{
    Logger::Log(Enums::LogLevel::INFO, "Daemon shutting down hard");

    for (auto thread : threads) {
        if (pthread_cancel(thread) != 0)
        {
            perror("pthread_cancel");
            exit(1);
        }
    }
    exit(0);
}

void Daemon::set_graceful_shutdown(int signum)
{
    Daemon::shutdown = true;
}

void Daemon::graceful_shutdown()
{
    Logger::Log(Enums::LogLevel::INFO, "Daemon shutting down gracefully");
    for (auto thread : threads) {
        if (pthread_join(thread, NULL) != 0)
        {
            perror("pthread_join");
            exit(1);
        }
    }
    exit(0);
}

void *Daemon::handle_connection(void* arg)
{
    int fd = *(int*) arg;

    pthread_cleanup_push(close_fd, &fd);

    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGTERM);
    sigaddset(&set, SIGQUIT);
    if (pthread_sigmask(SIG_SETMASK, &set, NULL) != 0)
    {
        perror("pthread_sigmask");
        exit(1);
    }

    // Handling
    std::cout << "Handling connection" << std::endl;
    sleep(1);


    pthread_cleanup_pop(1);
    return NULL;
}

void Daemon::close_fd(void* arg)
{
    int fd = *(int*) arg;
    if (close(fd) == -1)
    {
        perror("close");
    }
}
