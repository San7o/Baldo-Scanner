#include "daemon/kernel.hpp"
#include "daemon/daemon.hpp"
#include "common/logger.hpp"

using namespace AV;

struct nl_sock *Kernel::sk = NULL;
int Kernel::family_id = -1;

void Kernel::Init()
{
    /* create netlink socket */
    Kernel::sk = nl_socket_alloc();
    if (!Kernel::sk)
    {
        Logger::Log(Enums::LogLevel::ERROR, "nl_socket_alloc");
        exit(1);
    }

    /* Connect to generic netlink socket */
    int ret;
    ret = genl_connect(Kernel::sk);
    if (ret < 0)
    {
        nl_perror(ret, "genl_connect");
        nl_socket_free(Kernel::sk);
        exit(1);
    }

    /* Resolve the family ID */
    Kernel::family_id = genl_ctrl_resolve(Kernel::sk, AV_FAMILY_NAME);
    if (Kernel::family_id < 0)
    {
        nl_perror(Kernel::family_id, "genl_ctrl_resolve");
        nl_socket_free(Kernel::sk);
        exit(1);
    }

    Logger::Log(Enums::LogLevel::DEBUG, "Kernel initialized");
}

void Kernel::listen_kernel()
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
    Daemon::threads.push_back(thread);
    Daemon::threads_mutex.unlock();

    if (pthread_attr_destroy(&attr))
    {
        perror("pthread_attr_destroy");
    }
}

void *Kernel::thread_listen_kernel(void* arg)
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

    if (Kernel::family_id < 0)
    {
        Logger::Log(Enums::LogLevel::ERROR, "Family ID not resolved");
        pthread_exit(NULL);
    }
    if (!Kernel::sk)
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
    if (!genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, Kernel::family_id, 0, 0, AV_HELLO_CMD, 1))
    {
        Logger::Log(Enums::LogLevel::ERROR, "genlmsg_put");
        pthread_exit(NULL);
    }

    /* Send the message */
    int ret = nl_send_auto(Kernel::sk, msg);
    if (ret < 0)
    {
        nl_perror(ret, "nl_send_auto");
        pthread_exit(NULL);
    }
    Logger::Log(Enums::LogLevel::DEBUG, "Sent HELLO message to kernel");

    /* Register the callback */
    nl_socket_modify_cb(Kernel::sk, NL_CB_MSG_IN, NL_CB_CUSTOM, kernel_msg_callback, NULL);
    //nl_socket_set_nonblocking(sk);

    struct timespec tim;
    tim.tv_sec = 0;
    tim.tv_nsec = 100000000;

    Logger::Log(Enums::LogLevel::DEBUG, "Listening to kernel messages");

    /* Receive the message on the default handler */
    while (!Daemon::stop) {

        /* send fetch message */

        struct nl_msg *fetch_msg;
        fetch_msg = nlmsg_alloc();
        if (!fetch_msg)
        {
            Logger::Log(Enums::LogLevel::ERROR, "nlmsg_alloc in loop");
            pthread_exit(NULL);
        }

        /* Construct the messge */
        if (!genlmsg_put(fetch_msg, NL_AUTO_PID, NL_AUTO_SEQ, Kernel::family_id, 0, 0, AV_FETCH_CMD, 1))
        {
            Logger::Log(Enums::LogLevel::ERROR, "genlmsg_put in loop");
            pthread_exit(NULL);
        }

        /* Send the message */
        ret = nl_send_auto(Kernel::sk, fetch_msg);
        if (ret < 0)
        {
            nl_perror(ret, "nl_send_auto in loop");
            pthread_exit(NULL);
        }

        nl_recvmsgs_default(Kernel::sk);

        nanosleep(&tim, NULL);
        free_nlmsg(fetch_msg);
    }

    Logger::Log(Enums::LogLevel::DEBUG, "Stopped listening to kernel messages");

    free_nl_socket(Kernel::sk);
    pthread_cleanup_pop(1);
    return NULL;
}

int Kernel::kernel_msg_callback(struct nl_msg *msg, void *arg) {
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
        if (message == "") return NL_OK;
        Logger::Log(Enums::LogLevel::DEBUG, "Received message from kernel: " + message);
    }

    return NL_OK;
}

void Kernel::stop_kernel_netlink()
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
    if (!genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, Kernel::family_id, 0, 0, AV_BYE_CMD, 1))
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
    nl_close(Kernel::sk);
    free_nl_socket(Kernel::sk);
    Logger::Log(Enums::LogLevel::DEBUG, "Sent BYE message to kernel");
}

void Kernel::free_nl_socket(void* arg)
{
    struct nl_sock *sk = (struct nl_sock*) arg;
    nl_socket_free(sk);
}

void Kernel::free_nlmsg(void* arg)
{
    struct nl_msg *msg = (struct nl_msg*) arg;
    nlmsg_free(msg);
}
