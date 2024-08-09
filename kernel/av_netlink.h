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
enum {
    AV_UNSPEC,
    AV_MSG,   /* String message */
    __AV_MAX,
};
#define AV_MAX (__AV_MAX - 1)

/* A policy for the family */
static struct nla_policy av_genl_policy[AV_MAX + 1] = {
    [AV_MSG] = { .type = NLA_NUL_STRING }, /* Null terminated strings */
};

/* Operation handlers */
static int av_genl_hello(struct sk_buff *skb, struct genl_info *info);
static int av_genl_bye(struct sk_buff *skb, struct genl_info *info);
static int av_genl_fetch(struct sk_buff *skb, struct genl_info *info);

/* Operation Commands */
enum {
    AV_UNSPEC_CMD,
    AV_HELLO_CMD,   /* hello command,  requests connection */
    AV_BYE_CMD,     /* bye command,    close connection */
    AV_FETCH_CMD,   /* fetch command,  fetch files */
    __AV_MAX_CMD,
};
#define AV_MAX_CMD (__AV_MAX_CMD - 1)

/* Operation definition */
static struct genl_ops av_genl_ops[] = {
    {
        .cmd = AV_HELLO_CMD,
        .flags = 0,
        .policy = av_genl_policy,
        .doit = av_genl_hello,
        .dumpit = NULL,
    },
    {
        .cmd = AV_BYE_CMD,
        .flags = 0,
        .policy = av_genl_policy,
        .doit = av_genl_bye,
        .dumpit = NULL,
    },
    {
        .cmd = AV_FETCH_CMD,
        .flags = 0,
        .policy = av_genl_policy,
        .doit = av_genl_fetch,
        .dumpit = NULL,
    },
};

/* Family definition: a family is a group of commands and
 * associated operations. */
static struct genl_family av_genl_family = {
    .id = 0,           /* Automatica ID generation */
    .hdrsize = 0,
    .name = AV_FAMILY_NAME,
    .version = 1,
    .maxattr = AV_MAX,
    .ops = av_genl_ops,
    .n_ops = ARRAY_SIZE(av_genl_ops),
    .parallel_ops = 0,
};
#endif
