#pragma once

#include <thread>

/* libnl */
#include <netlink/netlink.h>
#include <netlink/cache.h>
#include <netlink/route/link.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <netlink/attr.h>
#include <netlink/msg.h>

#include "common/settings.hpp"

namespace AV
{

/*
 * This file contains the code responsible
 * for the communication with the kernel module.
 *
 * The communication is handled with generic sockets,
 * using the libnl library. The kernel registers a new
 * netlink family to handle the connection.
 */
#define AV_FAMILY_NAME "AV_GENL"
#define NETLINK_AV_GROUP 1

/*
 * The family is registered with the following commands:
 * - AV_HELLO_CMD: starts the connection, the kernel begins to
 *                 capture information regarding registered
 *                 systemcalls.
 * - AV_BYE_CMD:   closes the connection, the kernel stops capturing
 *                 information.
 * - AV_FETCH_CMD: fetches the information captured by the kernel.
 */
enum
{
    AV_UNSPEC_CMD,     /* no specific message     */
    AV_HELLO_CMD,      /* start capturing         */
    AV_BYE_CMD,        /* stop capturing          */
    AV_FETCH_CMD,      /* fetch data              */
    AV_BLOCK_IP_CMD,   /* submit an IP to block   */
    AV_UNBLOCK_IP_CMD, /* submit an IP to unblock */
    __AV_MAX_CMD,
};
#define AV_MAX_CMD (__AV_MAX_CMD - 1) /* Max value of the enum */

/*
 * The family also defines the followings attributes:
 * - AV_MSG: a null terminated string
 *
 * Attributes are sent as payload to a message and
 * a command.
 */
enum
{
    AV_UNSPEC,
    AV_MSG,   /* String message */
    AV_IPv4,  /* IPv4 address, u32 */
    __AV_MAX,
};
#define AV_MAX (__AV_MAX - 1) /* Max value of the enum */

/* Kernel related functions */
class Kernel
{
public:

Kernel() = delete; /* Singleton */

/* 
 * The socket responsible for communication
 * with the kernel
 */
static struct nl_sock *sk;
static int family_id;

/* 
 * Allocate the connection and resolve
 * the family ID. This function must
 * be called before any other function
 * in this class.
 */
static void Init();

/* 
 * Send an ip to the kerenl. This will be added to a
 * table of blocked ips. The kernel will block any
 * packet from that ip.
 */
static void send_ip_to_firewall(uint32_t ipv4, Enums::IpAction action);
/* 
 * Create a new thread with `thread_listen_kernel`
 */
static void listen_kernel();

/*
 * Thread function that listens for netlink messages.
 *
 * This function sends an AV_HELLO_CMD to the kernel,
 * which will start capturing information. It will
 * then loop and receive messages until Daemon::stop
 * is set to true. Note that this function blocks the
 * thread, therefore the connection needs to be closed
 * by calling nl_close() or nl_free(), this is done
 * by the graceful and hard shutdown functions.
 */
static void *thread_listen_kernel(void* arg);

/* 
 * This function gets called when a message
 * is received from the kernel. It reads the
 * headers and the message payload.
 */
static int kernel_msg_callback(struct nl_msg *msg, void *arg);

/*
 * This function stops the netlink connection by
 * sending a AV_BYE_CMD command to the kernel. The
 * kernel will stop capturing information.
 * This function takes care of freeing the socket,
 * it is called by the gracefun stutdown and hard
 * shutdown funcitons.
 */
static void stop_kernel_netlink();

/* Free function */
static void free_nl_socket(void* arg);
static void free_nlmsg(void* arg);

};

}
