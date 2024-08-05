#include "daemon/daemon.hpp"
#include "common/logger.hpp"

using namespace AV;

int main(int argc, char** argv)
{
    Daemon::Init();

    Logger::SetLogLevel(Enums::LogLevel::DEBUG);

    Daemon::listen_kernel();

    while(!Daemon::stop)
    {
        Daemon::listen_socket();
    }

    Daemon::graceful_shutdown();
    return 0;
}
