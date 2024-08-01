#pragma once

#define DB_PATH "/etc/antivirus/signatures.db"

#include "common/settings.hpp"
#include "daemon/malware_db.hpp"
#include <string>

namespace AV 
{

struct ScanRequest
{
    std::string filePath;
    Enums::ScanType scanType;
};

class Engine
{
public:
    std::string filePath;

    Engine(std::string filePath);

    void scan(Enums::ScanType);
    void scanSignature();
    void scanYaraRules();
};

}
