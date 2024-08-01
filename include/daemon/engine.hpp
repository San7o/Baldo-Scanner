#pragma once

#define DB_PATH "/etc/antivirus/signatures.db"

#include "common/settings.hpp"
#include "daemon/malware_db.hpp"
#include <string>
#include <mutex>

namespace AV 
{

struct ScanReport
{
    std::string report;
    std::mutex report_mutex;
    void append(std::string);
    void append(const unsigned char*);
};

struct ScanRequest
{
    std::string filePath;
    Enums::ScanType scanType;
    ScanReport* report;
};

class Engine
{
public:
    std::string filePath;
    ScanReport* report;

    Engine(std::string filePath, ScanReport* report);

    void scan(Enums::ScanType);
    void scanSignature();
    void scanYaraRules();
};

}
