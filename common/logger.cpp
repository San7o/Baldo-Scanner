// SPDX-License-Identifier: MIT
// Author:  Giovanni Santini
// Mail:    giovanni.santini@proton.me
// Github:  @San7o

#include <baldo/common/logger.hpp>

#include <filesystem>
#include <cerrno>
#include <time.h>

using namespace baldo;

FILE* Logger::log_file;
Enums::LogLevel Logger::log_level;

void Logger::Init()
{
  Logger::log_level = Enums::LogLevel::INFO;
    
  auto path = std::filesystem::absolute("/tmp/av-logs.txt");
  Logger::SetLogFile(path);
  return;
}

void Logger::Log(Enums::LogLevel level, std::string message)
{
  if (level >= Logger::log_level)
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
    case Enums::LogLevel::OUT:
      std::cout << "OUT: ";
      break;
    case Enums::LogLevel::REPORT:
      std::cout << "REPORT: ";
      break;
    default:
      break;
    }
    std::cout << message << std::endl;

    if (Logger::log_file != nullptr)
    {
      switch (level)
      {
      case Enums::LogLevel::DEBUG:
        fprintf(Logger::log_file, "DEBUG: ");
        break;
      case Enums::LogLevel::INFO:
        fprintf(Logger::log_file, "INFO: ");
        break;
      case Enums::LogLevel::WARN:
        fprintf(Logger::log_file, "WARN: ");
        break;
      case Enums::LogLevel::ERROR:
        fprintf(Logger::log_file, "ERROR: ");
        break;
      case Enums::LogLevel::OUT:
        fprintf(Logger::log_file, "OUT: ");
        break;
      case Enums::LogLevel::REPORT:
        fprintf(Logger::log_file, "REPORT: ");
        break;
      default:
        break;
      }
      fprintf(Logger::log_file, "%s\n", message.c_str());
    }
  }

  return;
}

void Logger::SetLogLevel(Enums::LogLevel level)
{
  Logger::log_level = level;
  return;
}

void Logger::SetLogFile(std::string path)
{
  Logger::log_file = fopen(path.c_str(), "a+");
  if (Logger::log_file == nullptr)
  {
    perror("fopen");
    return;
  }
  
  time_t now = time(&now);
  struct tm ltm;
  localtime_r(&now, &ltm);
  fprintf(Logger::log_file, "============%04d/%02d/%02d-%02d:%02d==========\n",
          ltm.tm_year + 1900, ltm.tm_mon, ltm.tm_mday, ltm.tm_hour, ltm.tm_min);
  return;
}
