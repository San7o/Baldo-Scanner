// SPDX-License-Identifier: GPL-2.0+
// Author:  Giovanni Santini
// Mail:    giovanni.santini@proton.me
// Github:  @San7o

#ifndef _BALDO_MAIN_H
#define _BALDO_MAIN_H

/* Kernel headers */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/uaccess.h>     /* copy_from_user */
#include <linux/slab.h>        /* kmalloc */
#include <uapi/asm/ptrace.h>   /* pt_regs for i386 */
#include <linux/kallsyms.h>    /* kallsyms_lookup_name */
#include <linux/spinlock.h>    /* spinlocks */
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>

#define MODULE_NAME "baldo"
#define BALDO_DEV_FIREWALL_NAME "baldo_firewall"
#define BALDO_DEV_NOTIFY_NAME "baldo_notify"

int __init baldo_init(void);
void __exit baldo_exit(void);

#endif // _BALDO_MAIN_H
