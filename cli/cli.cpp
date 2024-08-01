#include "cli/cli.hpp"
#include "common/logger.hpp"
#include <boost/program_options.hpp>
#include <iostream>
#include <sys/socket.h>
#include <cerrno>

using namespace AV;
namespace po = boost::program_options;

Settings Cli::settings = 
{
    Enums::ScanType::ALL,
    false,
    false,
    false,
    false,
    true,
    {},
    {},
    {}
};

void Cli::Init(int argc, char** argv)
{
    Cli::ParseArgs(argc, argv);

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == -1)
    {
        perror("socket");
        exit(1);
    }

    struct sockaddr_un addr;
    addr.sun_family = AF_UNIX;
    if (strcpy(addr.sun_path, SOCK_PATH) == NULL)
    {
        perror("strcpy");
        exit(1);
    }
    if (connect(fd, (struct sockaddr*) &addr, sizeof(addr)) == -1)
    {
        perror("bind");
        exit(1);
    }

    /*
    Logger::Log(Enums::LogLevel::DEBUG,
                    "Size of settings: " + std::to_string(sizeof(Cli::settings)));
    */

    if (send(fd, &Cli::settings, sizeof(Cli::settings), 0) == -1)
    {
        perror("send");
        exit(1);
    }
    else
    {
        char buf[1024];
        while (recv(fd, buf, sizeof(buf), 0) > 0)
        {
           Logger::Log(Enums::LogLevel::INFO, buf);
        }
    }
}

void Cli::ParseArgs(int argc, char** argv)
{

    po::options_description generic("Generic options");
    generic.add_options()
        ("help,h", "produce help message and exit")
        ("version,v", "print version information and exit");

    po::options_description daemon_options("Daemon options");
    daemon_options.add_options()
        ("update,u", "update Malware signatures database")
        ("quit,q", "quit daemon");

    po::options_description scan_options("Scan Options");
    scan_options.add_options()
        ("scan,s", po::value<std::string>(), "scan a file or directory")
        ("type,t", po::value<int>(), "type of scan: 0=signature 1=rules, 2=all[default]")
        ("load,l", po::value<std::string>(), "load signatures CSV")
        ("yara-rules,y", po::value<std::string>(), "set directory of yara rules")
        ("no-multithread", "disable multithreading");

    po::options_description desc("Allowed options");
    desc.add(generic).add(daemon_options).add(scan_options);

    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc), vm);
    po::notify(vm);

    if (vm.count("help"))
    {
        std::cout << desc << std::endl;
        exit(0);
    }

    if (vm.count("quit"))
    {
        Cli::settings.quit = true;
    }

    if (vm.count("version"))
    {
        Cli::settings.version = true;
    }

    if (vm.count("no-multithread"))
    {
        Cli::settings.multithread = false;
    }

    if (vm.count("yara-rules"))
    {
        std::string path = vm["yara-rules"].as<std::string>();
        if (strcpy(Cli::settings.yaraRulesPath, path.c_str()) == NULL)
        {
            perror("strcpy");
            exit(1);
        }
    }

    if (vm.count("load"))
    {
        std::string path = vm["load"].as<std::string>();
        if (strcpy(Cli::settings.signaturesPath, path.c_str()) == NULL)
        {
            perror("strcpy");
            exit(1);
        }
    }

    if (vm.count("scan"))
    {
        Cli::settings.scan = true;
        std::string path = vm["scan"].as<std::string>();
        if (strcpy(Cli::settings.scanFile, path.c_str()) == NULL)
        {
            perror("strcpy");
            exit(1);
        }
    }

    if (vm.count("type"))
    {
        int type = vm["type"].as<int>();
        switch (type)
        {
            case 0:
                Cli::settings.scanType = Enums::ScanType::SIGNATURE;
                break;
            case 1:
                Cli::settings.scanType = Enums::ScanType::RULES;
                break;
            case 2:
                Cli::settings.scanType = Enums::ScanType::ALL;
                break;
            default:
                Logger::Log(Enums::LogLevel::ERROR, "Invalid scan type");
                exit(1);
        }
    }

    if (vm.count("update"))
    {
        Cli::settings.update = true;
    }
}
