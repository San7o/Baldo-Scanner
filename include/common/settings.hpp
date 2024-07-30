#pragma once
#define MAX_PATH 1024

namespace AV {

namespace Enums {

enum class ScanType {
    SIGNATURE = 0,
    ROULES,
    ALL
};

} // namespace Enums

struct Settings {
     Enums::ScanType scanType;
     bool quit;
     bool update;
     bool version;
     bool scan;
     char scanFile[MAX_PATH];
     char yaraRulesPath[MAX_PATH];
     char signaturesPath[MAX_PATH];
};

} // namespace AV
