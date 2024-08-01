#pragma once
#define MAX_PATH 1024

namespace AV
{

namespace Enums
{

enum class ScanType
{
    SIGNATURE = 0,
    RULES,
    ALL
};

} // namespace Enums

struct Settings
{
     Enums::ScanType scanType;
     bool quit;
     bool force_quit;
     bool update;
     bool version;
     bool scan;
     bool multithread;
     char scanFile[MAX_PATH];
     char yaraRulesPath[MAX_PATH];
     char signaturesPath[MAX_PATH];
};

} // namespace AV
