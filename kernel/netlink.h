// SPDX-License-Identifier: GPL-2.0+
// Author:  Giovanni Santini
// Mail:    giovanni.santini@proton.me
// Github:  @San7o

#ifndef _BALDO_NETLINK_H
#define _BALDO_NETLINK_H

#ifdef BALDO_NETLINK

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

#define BALDO_FAMILY_NAME "BALDO_GENL"
#define NETLINK_BALDO_GROUP 31

/**
 * Here we are creating a family for the netlink communication,
 * we will be able to send predefined commands to the kernel module
 * from the user space.
 */

/* attribute types: values passed with a command */
enum
{
  BALDO_UNSPEC,
  BALDO_MSG,   /* String message */
  BALDO_IPv4,  /* IPv4 address, u32 */
  BALDO_DATA,  /* Data buffer */
  __BALDO_MAX,
};
#define BALDO_MAX (__BALDO_MAX - 1)

/* A policy for the family */
extern struct nla_policy baldo_genl_policy[BALDO_MAX + 1];

/* Operation handlers */
int baldo_genl_hello(struct sk_buff *skb, struct genl_info *info);
int baldo_genl_bye(struct sk_buff *skb, struct genl_info *info);
int baldo_genl_fetch(struct sk_buff *skb, struct genl_info *info);
int baldo_genl_block_ip(struct sk_buff *skb, struct genl_info *info);
int baldo_genl_unblock_ip(struct sk_buff *skb, struct genl_info *info);

/* Operation Commands */
enum
{
  BALDO_UNSPEC_CMD,
  BALDO_HELLO_CMD,        /* hello command:      requests connection */
  BALDO_BYE_CMD,          /* bye command:        close connection */
  BALDO_FETCH_CMD,        /* fetch command:      fetch files */
  BALDO_BLOCK_IP_CMD,     /* block ip command:   submit an IP to block */
  BALDO_UNBLOCK_IP_CMD,   /* unblock ip command: submit an IP to unblock */
  __BALDO_MAX_CMD,
};
#define BALDO_MAX_CMD (__BALDO_MAX_CMD - 1)

/* Operation definition */
extern struct genl_ops baldo_genl_ops[];

/* Family definition: a family is a group of commands and
 * associated operations. */
extern struct genl_family baldo_genl_family;

#endif // BALDO_NETLINK

#endif // _BALDO_NETLINK_H 
