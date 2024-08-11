#include "daemon/kernel.hpp"
#include "daemon/daemon.hpp"
#include "common/logger.hpp"
#include "common/utils.hpp"

#include <sqlite3.h>
#include <fstream>

using namespace AV;

struct nl_sock *Kernel::sk = NULL;
int Kernel::family_id = -1;
struct nla_policy Kernel::av_genl_policy[AV_MAX + 1];
sqlite3* Kernel::connection = nullptr;

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

    /* Setup policies */
    Kernel::av_genl_policy[AV_MSG]  = { .type = NLA_NUL_STRING };  /* Null terminated strings */
    Kernel::av_genl_policy[AV_IPv4] = { .type = NLA_U32 };         /* 32-bit unsigned integers */
    Kernel::av_genl_policy[AV_DATA] = { .type = NLA_BINARY };      /* Binary data */

    /* Initialize connection with db */
    char* errMsg = nullptr;
    if(!std::filesystem::exists(KERNEL_DB))
    {
        std::ofstream file(KERNEL_DB);
        file.close();
    }
    ret = sqlite3_open(KERNEL_DB, &connection);
    if (ret != SQLITE_OK)
    {
        Logger::Log(Enums::LogLevel::ERROR, "Can't open database: " + std::string(sqlite3_errmsg(connection)));
        sqlite3_close(connection);
        exit(1);
    }
    
    /* Create a table if it doesn't exist */
    std::string createTableSQL = "CREATE TABLE IF NOT EXISTS kdata("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, pid INT, ppid INT,"
            "tgid INT,uid INT, symbol TEXT, data TEXT);";
    ret = sqlite3_exec(connection, createTableSQL.c_str(), nullptr, nullptr, &errMsg);
    check_sqlite_error(ret, connection);

    /* Resolve the family ID */
    Kernel::family_id = genl_ctrl_resolve(Kernel::sk, AV_FAMILY_NAME);
    if (Kernel::family_id < 0)
    {
        nl_perror(Kernel::family_id, "genl_ctrl_resolve");
        Logger::Log(Enums::LogLevel::WARN, "Perhaps the kernel module is not loaded?");
        nl_socket_free(Kernel::sk);
    }
    else {
        Logger::Log(Enums::LogLevel::DEBUG, "Kernel initialized");
    }
}

void Kernel::listen_kernel()
{
    if (Kernel::family_id < 0)
    {
        return;
    }

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

void Kernel::send_ip_to_firewall(uint32_t ipv4, Enums::IpAction action)
{
    if (Kernel::family_id < 0)
    {
        return;
    }

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
    
    if (action == Enums::IpAction::BLOCK)
    {
        /* Send BLOCK message to kernel */
        if (!genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ,
                                Kernel::family_id, 0, 0, AV_BLOCK_IP_CMD, 1))
        {
            Logger::Log(Enums::LogLevel::ERROR, "genlmsg_put");
            return;
        }
    }
    else if (action == Enums::IpAction::UNBLOCK)
    {
        /* Send UNBLOCK message to kernel */
        if (!genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ,
                                Kernel::family_id, 0, 0, AV_UNBLOCK_IP_CMD, 1))
        {
            Logger::Log(Enums::LogLevel::ERROR, "genlmsg_put");
            return;
        }
    }

    /* Sending the IP */
    NLA_PUT_U32(msg, AV_IPv4, ipv4);

    ret = nl_send_auto(bye_sk, msg);
    if (ret < 0)
    {
        nl_perror(ret, "nl_send_auto");
        return;
    }
    nlmsg_free(msg);
    free_nl_socket(bye_sk);
    Logger::Log(Enums::LogLevel::DEBUG, "Sent IP " + std::to_string(ipv4) + " to kernel");
    return;

nla_put_failure:
    nlmsg_free(msg);
    free_nl_socket(bye_sk);
    Logger::Log(Enums::LogLevel::ERROR, "nla_put_failure");
    return;
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
    nl_socket_set_nonblocking(Kernel::sk);

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
    if (attrs[AV_DATA])
    {
        struct call_data_buffer_s *call_data_buffer = (struct call_data_buffer_s*) nla_data(attrs[AV_DATA]);
        //print_call_data_buffer(call_data_buffer);
        Kernel::save_kernel_data(call_data_buffer);
    }

    return NL_OK;
}

void Kernel::stop_kernel_netlink()
{
    if (Kernel::family_id < 0)
    {
        return;
    }

    /* Close connection with db */
    sqlite3_close(connection);

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

void Kernel::save_kernel_data(struct call_data_buffer_s *data)
{
    /* Start a transaction */
    int rc;
    rc = sqlite3_exec(connection, "BEGIN TRANSACTION;", nullptr, nullptr, nullptr);
    check_sqlite_error(rc, connection);

    /* Prepare the insert statement */
    std::string insert_sql = "INSERT INTO kdata(pid, ppid, tgid, uid, symbol, data) VALUES(?, ?, ?, ?, ?, ?);";
    sqlite3_stmt* stmt;

    rc = sqlite3_prepare_v2(connection, insert_sql.c_str(), -1, &stmt, nullptr);
    check_sqlite_error(rc, connection);

    /* Insert data into the table */
    for (int i = 0; i < data->num; i++)
    {
        rc = sqlite3_bind_int(stmt, 1, data->data[i].pid);
        check_sqlite_error(rc, connection);
        rc = sqlite3_bind_int(stmt, 2, data->data[i].ppid);
        check_sqlite_error(rc, connection);
        rc = sqlite3_bind_int(stmt, 3, data->data[i].tgid);
        check_sqlite_error(rc, connection);
        rc = sqlite3_bind_int(stmt, 4, data->data[i].uid);
        check_sqlite_error(rc, connection);
        rc = sqlite3_bind_text(stmt, 5, data->data[i].symbol, -1, SQLITE_TRANSIENT);
        check_sqlite_error(rc, connection);
        rc = sqlite3_bind_text(stmt, 6, data->data[i].data, -1, SQLITE_TRANSIENT);
        check_sqlite_error(rc, connection);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
    }

    /* Close transaction */
    rc = sqlite3_exec(connection, "END TRANSACTION;", nullptr, nullptr, nullptr);
    check_sqlite_error(rc, connection);
    
    Logger::Log(Enums::LogLevel::OUT, "Saved data to DB");
    sqlite3_finalize(stmt);
    return;
}

void Kernel::print_call_data_buffer(struct call_data_buffer_s *call_data_buffer)
{
    Logger::Log(Enums::LogLevel::DEBUG, "Num: " + std::to_string(call_data_buffer->num));
    for (int i = 0; i < call_data_buffer->num; i++)
    {
        Logger::Log(Enums::LogLevel::DEBUG, "Data: " + std::string(call_data_buffer->data[i].data));
        Logger::Log(Enums::LogLevel::DEBUG, "Symbol: " + std::string(call_data_buffer->data[i].symbol));
        Logger::Log(Enums::LogLevel::DEBUG, "PID: " + std::to_string(call_data_buffer->data[i].pid));
        Logger::Log(Enums::LogLevel::DEBUG, "PPID: " + std::to_string(call_data_buffer->data[i].ppid));
        Logger::Log(Enums::LogLevel::DEBUG, "TGID: " + std::to_string(call_data_buffer->data[i].tgid));
        Logger::Log(Enums::LogLevel::DEBUG, "UID: " + std::to_string(call_data_buffer->data[i].uid));
    }

}
