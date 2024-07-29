#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <cerrno>
#include <stdio.h>

#define SOCK_PATH "/tmp/av1"

int main(int argc, char** argv) {

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == -1) {
        std::cout << "Error: " << errno << std::endl;
    }


    struct sockaddr_un addr;
    addr.sun_family = AF_UNIX;
    if (strcpy(addr.sun_path, SOCK_PATH) == NULL) {
        std::cout << "Error: " << errno << std::endl;
    }
    if (connect(fd, (struct sockaddr*) &addr, sizeof(addr)) == -1) {
        perror("bind");
    }


}
