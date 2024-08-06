#include "daemon/daemon.hpp"
#include "daemon/kernel.hpp"
#include "common/logger.hpp"

using namespace AV;

int main(int argc, char** argv)
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
