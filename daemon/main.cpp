#include "daemon/daemon.hpp"
#include "common/logger.hpp"

using namespace AV;

int main(int argc, char** argv)
{
    Logger::Init();
    Daemon::Init();

    Logger::SetLogLevel(Enums::LogLevel::DEBUG);
    Logger::Log(Enums::LogLevel::INFO, "Daemon started");

    Daemon::listen_kernel();

    while(!Daemon::stop)
    {
        Daemon::listen_socket();
    }

    Daemon::graceful_shutdown();
    return 0;
}
