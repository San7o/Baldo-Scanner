#pragma once

#include <iostream>
#include <string>
#include <stdio.h>

namespace AV
{

namespace Enums
{

enum class LogLevel
{
    DEBUG,
    INFO,
    WARN,
    ERROR,
    OUT,
    REPORT
};

}

class Logger
{
public:
    static FILE* log_file;
    static Enums::LogLevel log_level;

    Logger() = delete;
    static void Init();
    static void Log(Enums::LogLevel level, std::string message);
    static void SetLogLevel(Enums::LogLevel level);
    static void SetLogFile(std::string file);
};

}
