#define _GNU_SOURCE
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/types.h>

int main(int argc, char **argv) {

    // Use openat to open the file relative to AT_FDCWD (current directory)
    const char* filename = "shell.nix";
    int fd = syscall(SYS_openat, AT_FDCWD, filename, O_RDONLY);
    if (fd < 0) {
        perror("openat");
        return 1;
    }

    int buff[10];
    ssize_t ret = syscall(SYS_read, fd, buff, 10);
    if (ret < 0) {
        perror("read");
        return 1;
    }

    if(write(STDOUT_FILENO, buff, ret) < 0) {
        perror("write");
        return 1;
    }

    close(fd);
    return 0;
}
