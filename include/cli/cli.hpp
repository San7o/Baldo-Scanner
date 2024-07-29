#pragma once
#define SOCK_PATH "/tmp/av1"

#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <cerrno>
#include <stdio.h>

namespace AV {

class Cli {
public:
    Cli() = delete;
    static std::string path;

    static void Init(); // TODO parse args
    static void ParseArgs(int argc, char** argv) {}
};

}
