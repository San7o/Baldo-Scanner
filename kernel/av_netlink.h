#ifndef _AV_NETLINK
#define _AV_NETLINK

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/uaccess.h>     /* copy_from_user */
#include <linux/slab.h>        /* kmalloc */
#include <uapi/asm/ptrace.h>   /* pt_regs for i386 */
#include <linux/kallsyms.h>    /* kallsyms_lookup_name */
#include <linux/spinlock.h>    /* spinlocks */
#include <linux/string.h>

#include <linux/netlink.h>     /* netlink_kernel_create, netlink_kernel_release */
#include <net/genetlink.h>     /* genl_register_family */
#include <net/netlink.h>       /* nla_put_string */

#define AV_FAMILY_NAME "AV_GENL"
#define NETLINK_AV_GROUP 31

/**
 * Here we are creating a family for the netlink communication,
 * we will be able to send predefined commands to the kernel module
 * from the user space.
 */

/* attribute types: values passed with a command */
enum
{
    AV_UNSPEC,
    AV_MSG,   /* String message */
    AV_IPv4,  /* IPv4 address, u32 */
    __AV_MAX,
};
#define AV_MAX (__AV_MAX - 1)

/* A policy for the family */
extern struct nla_policy av_genl_policy[AV_MAX + 1];

/* Operation handlers */
int av_genl_hello(struct sk_buff *skb, struct genl_info *info);
int av_genl_bye(struct sk_buff *skb, struct genl_info *info);
int av_genl_fetch(struct sk_buff *skb, struct genl_info *info);
int av_genl_submit_ip(struct sk_buff *skb, struct genl_info *info);

/* Operation Commands */
enum
{
    AV_UNSPEC_CMD,
    AV_HELLO_CMD,   /* hello command,  requests connection */
    AV_BYE_CMD,     /* bye command,    close connection */
    AV_FETCH_CMD,   /* fetch command,  fetch files */
    AV_SUBMIT_IP_CMD,   /* submit command, submit an IP to block */
    __AV_MAX_CMD,
};
#define AV_MAX_CMD (__AV_MAX_CMD - 1)

/* Operation definition */
extern struct genl_ops av_genl_ops[];

/* Family definition: a family is a group of commands and
 * associated operations. */
extern struct genl_family av_genl_family;

#endif
