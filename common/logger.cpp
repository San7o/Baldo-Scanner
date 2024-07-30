#include "common/logger.hpp"

#include <filesystem>
#include <cerrno>
#include <time.h>

using namespace AV;

FILE* Logger::log_file;
Enums::LogLevel Logger::log_level;

void Logger::Init()
{
    log_level = Enums::LogLevel::INFO;
    auto path = std::filesystem::absolute("logs/log.txt");
    Logger::SetLogFile(path);
}

void Logger::Log(Enums::LogLevel level, std::string message)
{
    if (level >= log_level)
    {
        switch (level)
        {
            case Enums::LogLevel::DEBUG:
                std::cout << "DEBUG: ";
                break;
            case Enums::LogLevel::INFO:
                std::cout << "INFO: ";
                break;
            case Enums::LogLevel::WARN:
                std::cout << "WARN: ";
                break;
            case Enums::LogLevel::ERROR:
                std::cout << "ERROR: ";
                break;
            default:
                break;
        }
        std::cout << message << std::endl;

        if (log_file != nullptr)
        {
            time_t now = time(&now);
            struct tm ltm;
            localtime_r(&now, &ltm);
            fprintf(log_file, "============%d/%d/%d-%d:%d==========\n",
                            ltm.tm_year, ltm.tm_mon, ltm.tm_mday, ltm.tm_hour, ltm.tm_min);
            switch (level) {
                case Enums::LogLevel::DEBUG:
                    fprintf(log_file, "DEBUG: ");
                    break;
                case Enums::LogLevel::INFO:
                    fprintf(log_file, "INFO: ");
                    break;
                case Enums::LogLevel::WARN:
                    fprintf(log_file, "WARN: ");
                    break;
                case Enums::LogLevel::ERROR:
                    fprintf(log_file, "ERROR: ");
                    break;
                default:
                    break;
            }
            fprintf(log_file, "%s\n", message.c_str());
        }
    }
}

void Logger::SetLogLevel(Enums::LogLevel level)
{
    log_level = level;
}

void Logger::SetLogFile(std::string path)
{
    log_file = fopen(path.c_str(), "a+");
    if (log_file == nullptr)
    {
        perror("fopen");
    }
}
