#pragma once

#include "common/settings.hpp"
#include "daemon/malware_db.hpp"
#include <string>

namespace AV 
{

class Engine
{
public:
    std::string filePath;
    std::string yaraRulesPath;
    MalwareDB* db;

    Engine(std::string filePath, std::string yaraRulesPath, MalwareDB* db);

    void scan(Enums::ScanType);
    void scanSignature();
    void scanYaraRules();
    void stop();
};

}
