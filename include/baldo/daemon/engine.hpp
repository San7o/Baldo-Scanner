// SPDX-License-Identifier: MIT
// Author:  Giovanni Santini
// Mail:    giovanni.santini@proton.me
// Github:  @San7o

#pragma once

#include <baldo/common/settings.hpp>
#include <baldo/daemon/malware_db.hpp>

#include <string>
#include <mutex>

namespace baldo
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

} // namespace baldo
