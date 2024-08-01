#include "daemon/daemon.hpp"
#include "daemon/malware_db.hpp"
#include "common/logger.hpp"
#include "common/settings.hpp"
#include "daemon/engine.hpp"
#include "daemon/yara.hpp"

#include <unistd.h>
#include <thread>
#include <asm/types.h>
#include <filesystem>

#include <yara.h>
#include <linux/netlink.h>

using namespace AV;

const int Daemon::MAX_THREADS = std::thread::hardware_concurrency();
const std::string Daemon::version = VERSION;

int Daemon::fd;
int Daemon::fd_kernel;
int Daemon::available_threads;
bool Daemon::stop = false;
std::vector<pthread_t> Daemon::threads = {};
std::mutex Daemon::threads_mutex;
std::mutex Daemon::available_threads_mutex;

void Daemon::Init()
{
    if (!std::filesystem::exists(PROGRAM_PATH))
    {
        if (std::filesystem::create_directories(PROGRAM_PATH) == false)
        {
            perror("create_directory");
            exit(1);
        }
    }

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == -1)
    {
        perror("socket");
        exit(1);
    }

    if (std::filesystem::exists(SOCK_PATH))
    {
        std::filesystem::remove(SOCK_PATH);
    }
    
    struct sockaddr_un addr;
    addr.sun_family = AF_UNIX;
    if (strcpy(addr.sun_path, SOCK_PATH) == NULL)
    {
        perror("strcpy");
        exit(1);
    }

    if (bind(fd, (struct sockaddr*) &addr, sizeof(addr)) == -1)
    {
        perror("bind");
        exit(1);
    }

    struct sigaction sa;
    sa.sa_handler = set_graceful_shutdown;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);               // graceful shutdown

    struct sigaction sterm;
    sterm.sa_handler = hard_shutdown;
    sterm.sa_flags = 0;
    sigemptyset(&sterm.sa_mask);
    if (sigaction(SIGTERM, &sterm, NULL) == -1) // hard shutdown
    {
        perror("sigaction");
        exit(1);
    }
    if (sigaction(SIGQUIT, &sterm, NULL) == -1) // hard shutdown
    {
        perror("sigaction");
        exit(1);
    }

    if (yr_initialize() != ERROR_SUCCESS)
    {
        perror("yr_initialize");
        exit(1);
    }
}

void Daemon::listen_socket()
{
    if (listen(fd, 5) == -1)
    {
        perror("listen");
        close(fd);
        exit(1);
    }
    int new_fd = accept(fd, NULL, NULL);
    if (new_fd == -1)
    {
        perror("accept");
    }

    if (!Daemon::stop) {

        pthread_t thread;
        pthread_attr_t attr;
        if (pthread_attr_init(&attr) != 0)
        {
            perror("pthread_attr_init");
        }

        if (pthread_create(&thread, &attr, thread_handle_connection, &new_fd) != 0)
        {
            perror("pthread_create");
            exit(1);
        }
        Daemon::threads_mutex.lock();
        threads.push_back(thread);
        Daemon::threads_mutex.unlock();

        if (pthread_attr_destroy(&attr))
        {
            perror("pthread_attr_destroy");
        }
    }
}

void Daemon::listen_kernel()
{
    pthread_t thread;
    pthread_attr_t attr;
    if (pthread_attr_init(&attr) != 0)
    {
        perror("pthread_attr_init");
    }

    if (pthread_create(&thread, &attr, thread_listen_kernel, NULL) != 0)
    {
        perror("pthread_create");
        exit(1);
    }
    Daemon::threads_mutex.lock();
    threads.push_back(thread);
    Daemon::threads_mutex.unlock();

    if (pthread_attr_destroy(&attr))
    {
        perror("pthread_attr_destroy");
    }
}

void Daemon::hard_shutdown(int signum)
{
    Logger::Log(Enums::LogLevel::INFO, "Daemon shutting down hard");

    if (yr_finalize() != ERROR_SUCCESS)
    {
        perror("yr_finalize");
        exit(1);
    }

    shutdown(fd_kernel, SHUT_RDWR);


    for (auto thread : threads)
    {
        if (pthread_cancel(thread) != 0)
        {
            perror("pthread_cancel");
            exit(1);
        }
    }
    exit(0);
}

void Daemon::set_graceful_shutdown(int signum)
{
    Daemon::stop = true;
}

void Daemon::graceful_shutdown()
{
    Logger::Log(Enums::LogLevel::INFO, "Daemon shutting down gracefully");

    if (yr_finalize() != ERROR_SUCCESS)
    {
        perror("yr_finalize");
        exit(1);
    }

    shutdown(Daemon::fd_kernel, SHUT_RDWR);

    Daemon::threads_mutex.lock();
    for (auto thread : threads)
    {
        if (pthread_join(thread, NULL) != 0)
        {
            perror("pthread_join");
            exit(1);
        }
    }
    Daemon::threads_mutex.unlock();

    exit(0);
}

void Daemon::parse_settings(Settings settings, int fd)
{
    if (settings.quit)
    {
        graceful_shutdown();
    }
    if (settings.force_quit)
    {
        hard_shutdown(0);
    }
    else if (settings.version)
    {
        if (send(fd, VERSION, 7, 0) == -1) {
            perror("send");
            pthread_exit(NULL);
        }
    }
    else
    { 
        if (settings.update)
        {
            MalwareDB db("/etc/antivirus/signatures.db");
            db.update();
        }

        if (strlen(settings.signaturesPath) > 0)
        {
            MalwareDB db("/etc/antivirus/signatures.db");
            db.load(settings.signaturesPath);
        }
        
        if (strlen(settings.yaraRulesPath) > 0 )
        {
            Yara::CompileRules(settings.yaraRulesPath);
        }

        if (settings.scan)
        {   
            scanFiles(settings.scanFile, settings.scanType, settings.multithread);
        }
    }
}

void Daemon::scanFiles(std::string scanFile, Enums::ScanType scanType, bool multithreaded)
{ 
    if (!std::filesystem::exists(scanFile))
    {
        Logger::Log(Enums::LogLevel::ERROR, "File does not exist: " + scanFile);
        return;
    }

    if (!std::filesystem::is_directory(scanFile))
    {
        ScanRequest* request = new ScanRequest{scanFile, scanType};
        pthread_t thread;
        pthread_attr_t attr;
        if (pthread_attr_init(&attr) != 0)
        {
            perror("pthread_attr_init");
        }

        if (pthread_create(&thread, &attr, thread_scan, (void*) request) != 0)
        {
            perror("pthread_create");
            exit(1);
        }
        return;
    }

    Daemon::available_threads_mutex.lock();

    if (!multithreaded)
    {
        Daemon::available_threads = 1;
    }
    else
    {
        Daemon::available_threads = MAX_THREADS;

        if (Daemon::available_threads < 1)
        {
            Daemon::available_threads = 1;
        }
    }
    
    Daemon::available_threads_mutex.unlock();

    struct timespec tim;
    tim.tv_sec = 0;
    tim.tv_nsec = 1000000;

    for (auto file : std::filesystem::recursive_directory_iterator(scanFile))
    {
        if (Daemon::stop) break;

        if (std::filesystem::is_directory(file)) continue;

        Daemon::available_threads_mutex.lock();
        while(available_threads == 0)
        {
            Daemon::available_threads_mutex.unlock();
            nanosleep(&tim, NULL);
            Daemon::available_threads_mutex.lock();
        }

        ScanRequest* request = new ScanRequest{file.path(), scanType};
        available_threads--;
        
        pthread_t thread;
        pthread_attr_t attr;
        if (pthread_attr_init(&attr) != 0)
        {
            perror("pthread_attr_init");
        }

        if (pthread_create(&thread, &attr, thread_scan, (void*) request) != 0)
        {
            perror("pthread_create");
            exit(1);
        }

        Daemon::threads_mutex.lock();
        threads.push_back(thread);
        Daemon::threads_mutex.unlock();
        
        Daemon::available_threads_mutex.unlock();
    }
}

void Daemon::close_fd(void* arg)
{
    int *fd = (int*) arg;
    if (close(*fd) == -1)
    {
        perror("close");
    }
}

void *Daemon::thread_handle_connection(void* arg)
{
    int fd = *(int*) arg;

    pthread_cleanup_push(close_fd, arg);

    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGTERM);
    sigaddset(&set, SIGQUIT);
    if (pthread_sigmask(SIG_SETMASK, &set, NULL) != 0)
    {
        perror("pthread_sigmask");
        exit(1);
    }

    struct Settings settings;
    if (recv(fd, &settings, sizeof(Settings), 0) == -1)
    {
        perror("recv");
        pthread_exit(NULL);
    }

    Logger::Log(Enums::LogLevel::INFO, "Connection received");
    print_settings(settings);

    parse_settings(settings, fd);

    pthread_cleanup_pop(1);
    return NULL;
}

void *Daemon::thread_listen_kernel(void* arg)
{
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGTERM);
    sigaddset(&set, SIGQUIT);
    if (pthread_sigmask(SIG_SETMASK, &set, NULL) != 0)
    {
        perror("pthread_sigmask");
        exit(1);
    }

    Daemon::fd_kernel = socket(PF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
    if (fd_kernel == -1)
    {
        perror("netlink socket");
        exit(1);
    }

    pthread_cleanup_push(close_fd, &fd_kernel);

    struct sockaddr_nl src_addr;
    memset(&src_addr, 0, sizeof(src_addr));  
    src_addr.nl_family = AF_NETLINK;  
    src_addr.nl_pid = getpid();
    if (bind(fd_kernel, (struct sockaddr*)&src_addr, sizeof(src_addr)) == -1)
    {
        perror("bind");
        pthread_exit(NULL);
    }

    struct msghdr msg;
    while(!Daemon::stop && (recvmsg(fd_kernel, &msg, 0) > 0))
    {
        Logger::Log(Enums::LogLevel::DEBUG, "Kernel message received");
        // TODO: handle kernel message
    }

    pthread_cleanup_pop(1);
    return NULL;

}

void Daemon::free_request(void* arg)
{
    ScanRequest* request = (ScanRequest*) arg;
    delete request;
}

void *Daemon::thread_scan(void* arg)
{
    pthread_cleanup_push(free_request, arg);

    ScanRequest* request = (ScanRequest*) arg;
    Logger::Log(Enums::LogLevel::INFO, "Scanning file: " + request->filePath);

    Engine engine(request->filePath);

    engine.scan(request->scanType);

    Daemon::available_threads_mutex.lock();
    Daemon::available_threads++;
    Daemon::available_threads_mutex.unlock();

    pthread_cleanup_pop(1);
    return NULL;
}

void Daemon::print_settings(Settings settings)
{
    using namespace AV::Enums;
    using namespace std;
    Logger::Log(LogLevel::DEBUG, "Scan: "      + to_string(settings.scan));
    Logger::Log(LogLevel::DEBUG, "Scan type: " + to_string(static_cast<int>(settings.scanType)));
    Logger::Log(LogLevel::DEBUG, "Update: "    + to_string(settings.update));
    Logger::Log(LogLevel::DEBUG, "Version: "   + to_string(settings.version));
    Logger::Log(LogLevel::DEBUG, "Quit: "      + to_string(settings.quit));
    Logger::Log(LogLevel::DEBUG, "Multithread: " + to_string(settings.multithread));
    Logger::Log(LogLevel::DEBUG, "Scan file: " + string(settings.scanFile));
    Logger::Log(LogLevel::DEBUG, "Yara rules path: " + string(settings.yaraRulesPath));
    Logger::Log(LogLevel::DEBUG, "Signatures path: " + string(settings.signaturesPath));
}
