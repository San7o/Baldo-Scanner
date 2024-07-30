#include "daemon/daemon.hpp"
#include "common/logger.hpp"

using namespace AV;

int main(int argc, char** argv)
{
    Logger::Init();
    Daemon::Init();
    Logger::Log(Enums::LogLevel::INFO, "Daemon started");

    while(!Daemon::shutdown)
    {
        Daemon::listen_socket();
    }

    Daemon::graceful_shutdown();
    return 0;
}
