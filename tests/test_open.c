#define _GNU_SOURCE
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/types.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <file>\n", argv[0]);
        return 1;
    }

    // Use openat to open the file relative to AT_FDCWD (current directory)
    int fd = syscall(SYS_openat, AT_FDCWD, argv[1], O_RDONLY);
    if (fd < 0) {
        perror("openat");
        return 1;
    }

    printf("File opened\n");

    close(fd);
    return 0;
}
