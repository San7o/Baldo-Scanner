// SPDX-License-Identifier: MIT
// Author:  Giovanni Santini
// Mail:    giovanni.santini@proton.me
// Github:  @San7o

#include <baldo/daemon/daemon.hpp>
#include <baldo/daemon/kernel.hpp>
#include <baldo/common/logger.hpp>

using namespace baldo;

int main(void)
{
  Daemon::Init();

  Logger::SetLogLevel(Enums::LogLevel::DEBUG);

  Kernel::listen_kernel();

  while(!Daemon::stop)
  {
    Daemon::listen_socket();
  }

  Daemon::graceful_shutdown();
  return 0;
}
