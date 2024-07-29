
#include "daemon/daemon.hpp"
#include "common/logger.hpp"

using namespace AV;

int main(int argc, char** argv) {
  
    Daemon::Init();

    Logger::Init();
    Logger::Log(Enums::LogLevel::INFO, "Daemon started");

    while(1) {
        Daemon::listen_socket();
        Daemon::accept_connection();
    }

    return 0;
}
