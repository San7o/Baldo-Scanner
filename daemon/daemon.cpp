#include "daemon/daemon.hpp"

using namespace AV;

int Daemon::fd;
std::vector<pthread_t> Daemon::threads;

void Daemon::Init() {
fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == -1) {
        perror("socket");
    }
    if (std::filesystem::exists(SOCK_PATH)) {
        std::filesystem::remove(SOCK_PATH);
    }
    struct sockaddr_un addr;
    addr.sun_family = AF_UNIX;
    if (strcpy(addr.sun_path, SOCK_PATH) == NULL) {
        perror("strcpy");
    }
    if (bind(fd, (struct sockaddr*) &addr, sizeof(addr)) == -1) {
        perror("bind");
    }

    struct sigaction sa;
    sa.sa_handler = hard_shutdown;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);    // graceful shutdown
    struct sigaction sterm;
    sterm.sa_handler = hard_shutdown;
    sterm.sa_flags = 0;
    sigemptyset(&sterm.sa_mask);
    sigaction(SIGTERM, &sterm, NULL); // hard shutdown
    sigaction(SIGQUIT, &sterm, NULL); // hard shutdown
}
void Daemon::listen_socket() {
    if (listen(fd, 5) == -1) {
        perror("listen");
    }
}
void Daemon::accept_connection() {
    int new_fd = accept(fd, NULL, NULL);
    if (new_fd == -1) {
        perror("accept");
    }

    // Create new thread
    std::cout << "New connection" << std::endl;

    pthread_t thread;
    threads.push_back(thread);
    pthread_attr_t attr;
    if (pthread_attr_init(&attr) != 0) {
        perror("pthread_attr_init");
    }
    if (pthread_create(&thread, &attr, handle_connection, &new_fd) != 0) {
        perror("pthread_create");
    }
    pthread_attr_destroy(&attr);
    
}
void Daemon::hard_shutdown(int signum) {
    for (auto thread : threads) {
        if (pthread_cancel(thread) != 0) {
            perror("pthread_cancel");
        }
    }
    exit(0);
}
void Daemon::soft_shutdown(int signum) {
    for (auto thread : threads) {
        if (pthread_join(thread, NULL) != 0) {
            perror("pthread_join");
        }
    }
    exit(0);
}
void *Daemon::handle_connection(void* arg) {
    int fd = *(int*) arg;

    pthread_cleanup_push(close_fd, &fd);

    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGTERM);
    if (pthread_sigmask(SIG_SETMASK, &set, NULL) != 0) {
        perror("pthread_sigmask");
    }

    std::cout << "Handling connection" << std::endl;

    pthread_cleanup_pop(1);
    return NULL;
}
void Daemon::close_fd(void* arg) {
    int fd = *(int*) arg;
    close(fd);
}