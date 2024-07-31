#pragma once
#define SOCK_PATH "/tmp/av1"

#include "common/settings.hpp"

#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <cerrno>
#include <stdio.h>

namespace AV
{

class Cli
{
public:
    static struct Settings settings;

    Cli() = delete;

    static void Init(int argc, char** argv);
    static void ParseArgs(int argc, char** argv);
};

}
