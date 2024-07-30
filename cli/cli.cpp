#include "cli/cli.hpp"
#include "common/logger.hpp"
#include <boost/program_options.hpp>
#include <iostream>
#include <sys/socket.h>
#include <cerrno>

using namespace AV;
namespace po = boost::program_options;

struct Settings Cli::settings = {
    Enums::ScanType::ALL,
    false,
    false,
    false,
    {},
};

void Cli::Init(int argc, char** argv) {

    Cli::ParseArgs(argc, argv);

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == -1) {
        std::cout << "Error: " << errno << std::endl;
    }

    struct sockaddr_un addr;
    addr.sun_family = AF_UNIX;
    if (strcpy(addr.sun_path, SOCK_PATH) == NULL) {
        std::cout << "Error: " << errno << std::endl;
    }
    if (connect(fd, (struct sockaddr*) &addr, sizeof(addr)) == -1) {
        perror("bind");
    }

    if (send(fd, &Cli::settings, sizeof(Cli::settings), 0) == -1) {
        perror("send");
    }
    else {
        char buf[1024];
        if (recv(fd, buf, sizeof(buf), 0) == -1) {
            perror("recv");
        }
        else {
           Logger::Log(Enums::LogLevel::INFO, buf);
        }
    }
}

void Cli::ParseArgs(int argc, char** argv) {

    po::options_description generic("Generic options");
    generic.add_options()
        ("help,h", "produce help message and exit")
        ("version,v", "print version information and exit")
        ("update,u", "update Malware database");

    po::options_description scan_options("Scan Options");
    scan_options.add_options()
        ("scan,s", po::value<std::string>(), "scan a file")
        ("type,t", po::value<int>(), "type of scan: 0=signature 1=roules, 2=all[default]");

    po::options_description desc("Allowed options");
    desc.add(generic).add(scan_options);

    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc), vm);
    po::notify(vm);

    if (vm.count("help")) {
        std::cout << desc << std::endl;
        exit(0);
    }

    if (vm.count("version")) {
        Cli::settings.version = true;
    }

    if (vm.count("scan")) {
        Cli::settings.scan = true;
        std::string path = vm["scan"].as<std::string>();
        if (strcpy(Cli::settings.scanFile, path.c_str()) == NULL) {
            perror("strcpy");
            exit(1);
        }
    }

    if (vm.count("type")) {
        int type = vm["type"].as<int>();
        switch (type) {
            case 0:
                Cli::settings.scanType = Enums::ScanType::SIGNATURE;
                break;
            case 1:
                Cli::settings.scanType = Enums::ScanType::ROULES;
                break;
            case 2:
                Cli::settings.scanType = Enums::ScanType::ALL;
                break;
            default:
                std::cout << "Invalid scan type" << std::endl;
                exit(1);
        }
    }

    if (vm.count("update")) {
        Cli::settings.update = true;
    }
}
