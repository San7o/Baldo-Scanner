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
#include <sys/socket.h>

/* libnl */
#include <netlink/netlink.h>
#include <netlink/cache.h>
#include <netlink/route/link.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <netlink/msg.h>

#define NETLINK_AV_GROUP 1 // Same as in the kernel module
#define AV_FAMILY_NAME "AV_GENL"

using namespace AV;

const int Daemon::MAX_THREADS = std::thread::hardware_concurrency();
const std::string Daemon::version = VERSION;

int Daemon::fd;
int Daemon::family_id = -1;
int Daemon::available_threads;
bool Daemon::stop = false;
struct nl_sock *Daemon::sk = NULL;
std::vector<pthread_t> Daemon::threads = {};
std::mutex Daemon::threads_mutex;
std::mutex Daemon::available_threads_mutex;

void Daemon::Init()
{
    Logger::Init();
    Logger::Log(Enums::LogLevel::INFO, "Daemon starting");

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

    /* create netlink socket */
    sk = nl_socket_alloc();
    if (!sk)
    {
        Logger::Log(Enums::LogLevel::ERROR, "nl_socket_alloc");
        exit(1);
    }

    /* Connect to generic netlink socket */
    int ret;
    ret = genl_connect(sk);
    if (ret < 0)
    {
        nl_perror(ret, "genl_connect");
        nl_socket_free(sk);
        exit(1);
    }

    /* Resolve the family ID */
    family_id = genl_ctrl_resolve(sk, AV_FAMILY_NAME);
    if (family_id < 0)
    {
        nl_perror(family_id, "genl_ctrl_resolve");
        nl_socket_free(sk);
        exit(1);
    }

    Logger::Log(Enums::LogLevel::INFO, "Daemon started");
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

    stop_kernel_netlink();
    free_nl_socket(Daemon::sk);
    nl_close(Daemon::sk);

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

/* Do not add other routines here */
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

    stop_kernel_netlink();
    nl_close(Daemon::sk);

    for (auto thread : threads)
    {
        if (pthread_join(thread, NULL) != 0)
        {
            perror("pthread_join");
            exit(1);
        }
    }

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
            MalwareDB db(DB_PATH);
            db.update();
        }

        if (strlen(settings.signaturesPath) > 0)
        {
            MalwareDB db(DB_PATH);
            db.load(settings.signaturesPath);
        }
        
        if (strlen(settings.yaraRulesPath) > 0 )
        {
            Yara::CompileRules(settings.yaraRulesPath);
        }

        if (settings.scan)
        {   
            scan_files(settings.scanFile, settings.scanType, settings.multithread);
        }
    }
}

void Daemon::produce_report(ScanReport* report)
{
    std::cout << std::flush;
    if (report->report.length() > 0)
    {
        Logger::Log(Enums::LogLevel::REPORT, "MALWARE DETECTED\n" + report->report);
    }
    else
    {
        Logger::Log(Enums::LogLevel::REPORT, "No malware detected");
    }

    delete report;
}

void Daemon::scan_files(std::string scanFile, Enums::ScanType scanType, bool multithreaded)
{ 
    if (!std::filesystem::exists(scanFile))
    {
        Logger::Log(Enums::LogLevel::ERROR, "File does not exist: " + scanFile);
        return;
    }

    if (!std::filesystem::is_directory(scanFile))
    {
        ScanReport *report = new ScanReport{"", std::mutex()};
        ScanRequest* request = new ScanRequest{scanFile, scanType, report};

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

        if (pthread_join(thread, NULL) != 0)
        {
            perror("pthread_join");
            exit(1);
        }

        produce_report(report);
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

    ScanReport *report = new ScanReport{"", std::mutex()};
    std::vector<pthread_t> scan_threads;

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

        ScanRequest* request = new ScanRequest{file.path(), scanType, report};
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
        scan_threads.push_back(thread);

        Daemon::available_threads_mutex.unlock();
    }

    for (auto thread : scan_threads)
    {
        if (pthread_join(thread, NULL) != 0)
        {
            perror("pthread_join");
            exit(1);
        }
    }

    produce_report(report);
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

void Daemon::free_nl_socket(void* arg)
{
    struct nl_sock *sk = (struct nl_sock*) arg;
    nl_socket_free(sk);
}

void Daemon::free_nlmsg(void* arg)
{
    struct nl_msg *msg = (struct nl_msg*) arg;
    nlmsg_free(msg);
}

/* Generic netlink attributes */
enum {
    AV_UNSPEC,
    AV_MSG,   /* String message */
    __AV_MAX,
};
#define AV_MAX (__AV_MAX - 1)

/* kernel generic netlink commands */
enum {
    AV_UNSPEC_CMD,
    AV_HELLO_CMD,   /* hello command,  requests connection */
    AV_BYE_CMD,     /* bye command,    close connection */
    AV_FETCH_CMD,   /* fetch command,  fetch files */
    __AV_MAX_CMD,
};
#define AV_MAX_CMD (__AV_MAX_CMD - 1)

int Daemon::kernel_msg_callback(struct nl_msg *msg, void *arg) {
    struct nlmsghdr *nlh = nlmsg_hdr(msg);

    struct nlattr *attrs[AV_MAX + 1];
    if (nlh->nlmsg_type == NLMSG_ERROR)
    {
        struct nlmsgerr *err = (struct nlmsgerr*) nlmsg_data(nlh);
        if (err->error < 0)
        {
            Logger::Log(Enums::LogLevel::ERROR, "Error in message");
            return NL_STOP;
        }
    }

    struct genlmsghdr *gnlh = (struct genlmsghdr*) nlmsg_data(nlh);
    nla_parse(attrs, AV_MAX, genlmsg_attrdata(gnlh, 0),
                    genlmsg_attrlen(gnlh, 0), NULL);
    if (attrs[AV_MSG])
    {
        std::string message((char*) nla_data(attrs[AV_MSG]));
        Logger::Log(Enums::LogLevel::DEBUG, "Received message from kernel: " + message);
    }

    return NL_OK;
}

void Daemon::stop_kernel_netlink()
{
    /* create netlink socket */
    struct nl_sock* bye_sk = nl_socket_alloc();
    if (!bye_sk)
    {
        Logger::Log(Enums::LogLevel::ERROR, "nl_socket_alloc");
        exit(1);
    }

    /* Connect to generic netlink socket */
    int ret;
    ret = genl_connect(bye_sk);
    if (ret < 0)
    {
        nl_perror(ret, "genl_connect");
        nl_socket_free(bye_sk);
        exit(1);
    }
    /* Allocate a new netlink message */
    struct nl_msg *msg;
    msg = nlmsg_alloc();
    if (!msg)
    {
        Logger::Log(Enums::LogLevel::ERROR, "nlmsg_alloc");
        return;
    }

    /* Send BYE message to kernel */
    if (!genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family_id, 0, 0, AV_BYE_CMD, 1))
    {
        Logger::Log(Enums::LogLevel::ERROR, "genlmsg_put");
        return;
    }
    ret = nl_send_auto(bye_sk, msg);
    if (ret < 0)
    {
        nl_perror(ret, "nl_send_auto");
        return;
    }
    nlmsg_free(msg);
    free_nl_socket(bye_sk);
    Logger::Log(Enums::LogLevel::DEBUG, "Sent BYE message to kernel");
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

    if (family_id < 0)
    {
        Logger::Log(Enums::LogLevel::ERROR, "Family ID not resolved");
        pthread_exit(NULL);
    }
    if (!sk)
    {
        Logger::Log(Enums::LogLevel::ERROR, "Netlink socket not created");
        pthread_exit(NULL);
    }

    /* Allocate a new netlink message */
    struct nl_msg *msg;
    msg = nlmsg_alloc();
    if (!msg)
    {
        Logger::Log(Enums::LogLevel::ERROR, "nlmsg_alloc");
        pthread_exit(NULL);
    }

    pthread_cleanup_push(free_nlmsg, msg);

    /* Construct the messge */
    if (!genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family_id, 0, 0, AV_HELLO_CMD, 1))
    {
        Logger::Log(Enums::LogLevel::ERROR, "genlmsg_put");
        pthread_exit(NULL);
    }

    /* Send the message */
    int ret = nl_send_auto(sk, msg);
    if (ret < 0)
    {
        nl_perror(ret, "nl_send_auto");
        pthread_exit(NULL);
    }
    Logger::Log(Enums::LogLevel::DEBUG, "Sent HELLO message to kernel");

    /* Register the callback */
    nl_socket_modify_cb(sk, NL_CB_MSG_IN, NL_CB_CUSTOM, kernel_msg_callback, NULL);
    nl_socket_set_nonblocking(sk);

    /* Receive the message on the default handler */
    while (Daemon::stop == false) {

        /* send fetch message */

        struct nl_msg *fetch_msg;
        fetch_msg = nlmsg_alloc();
        if (!fetch_msg)
        {
            Logger::Log(Enums::LogLevel::ERROR, "nlmsg_alloc in loop");
            pthread_exit(NULL);
        }

        /* Construct the messge */
        if (!genlmsg_put(fetch_msg, NL_AUTO_PID, NL_AUTO_SEQ, family_id, 0, 0, AV_FETCH_CMD, 1))
        {
            Logger::Log(Enums::LogLevel::ERROR, "genlmsg_put in loop");
            pthread_exit(NULL);
        }

        /* Send the message */
        ret = nl_send_auto(sk, fetch_msg);
        if (ret < 0)
        {
            nl_perror(ret, "nl_send_auto in loop");
            pthread_exit(NULL);
        }

        nl_recvmsgs_default(sk);

        sleep(1);
        free_nlmsg(fetch_msg);
    }

    Logger::Log(Enums::LogLevel::DEBUG, "Received message from kernel");

    free_nl_socket(Daemon::sk);
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
    Logger::Log(Enums::LogLevel::OUT, "Scanning file: " + request->filePath);

    Engine engine(request->filePath, request->report);

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
