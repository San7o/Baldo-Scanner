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

void *handle_connection(void* fd) {

    sigset_t set;
	sigemptyset(&set);
	sigaddset(&set, SIGTERM);
	if (pthread_sigmask(SIG_SETMASK, &set, NULL) != 0) {
        perror("pthread_sigmask");
    }

    std::cout << "Handling connection" << std::endl;

    return NULL;
}

void sigterm_handler(int signum) {

    // TODO: deallocate and close connections

    exit(0);
}

int main(int argc, char** argv) {
  
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
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

    std::vector<pthread_t> threads;
    std::vector<pthread_attr_t> attrs;
    std::vector<int> fds;

    struct sigaction sa;
    sa.sa_handler = sigterm_handler;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);
    

    while(1) {
        if (listen(fd, 5) == -1) {
            perror("listen");
        }

        int new_fd = accept(fd, NULL, NULL);
        if (new_fd == -1) {
            perror("accept");
        }
        fds.push_back(new_fd);

        // Create new thread
        std::cout << "New connection" << std::endl;

        pthread_t thread;
        threads.push_back(thread);
        pthread_attr_t attr;
        attrs.push_back(attr);
        if (pthread_attr_init(&attr) != 0) {
            perror("pthread_attr_init");
        }
        if (pthread_create(&thread, &attr, handle_connection, &new_fd) != 0) {
            perror("pthread_create");
        }

    }

    // destroy allocation
    for (auto thread : threads) {
        pthread_join(thread, NULL);
    }
    for (auto fd : fds) {
        close(fd);
    }
    for (auto attr : attrs) {
        pthread_attr_destroy(&attr);
    }
    
    return 0;
}
