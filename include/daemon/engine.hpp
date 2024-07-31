#pragma once

#define DB_PATH "/etc/antivirus/signatures.db"

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

    Engine(std::string filePath, std::string yaraRulesPath);

    void scan(Enums::ScanType);
    void scanSignature();
    void scanYaraRules();
    void stop();
};

}
