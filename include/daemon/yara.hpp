#pragma once

#include "daemon/engine.hpp"

#include <string>
#include <yara.h>

namespace AV 
{

struct YaraUserData
{
    ScanReport* report;
    std::string path;
};

class Yara
{
public:

Yara() = delete; /* Singleton */

static void CompileRules(std::string yaraRulesPath);
static void LoadRules(std::string yaraRulesPath, YR_RULES** rules);
static void Scan(YR_RULES* rules, std::string path, ScanReport* report);

private:
static void callback_compilation(int error_level, const char* file_name, int line_number,
                       const YR_RULE* rule, const char* message, void* user_data);

static int callback_scan(YR_SCAN_CONTEXT* context, int message,
                     void* message_data, void* user_data);
};

}
