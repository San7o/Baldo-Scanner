// SPDX-License-Identifier: MIT
// Author:  Giovanni Santini
// Mail:    giovanni.santini@proton.me
// Github:  @San7o

#pragma once

#include <baldo/common/settings.hpp>

#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <cerrno>
#include <stdio.h>

#define SOCK_PATH "/tmp/av1"

namespace baldo
{

class Cli
{
public:
  static struct Settings settings;
  
  Cli() = delete;

  static void Init(int argc, char** argv);
  static void ParseArgs(int argc, char** argv);
};

}
