#include "cli/cli.hpp"

using namespace AV;

void Cli::Init() {
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
