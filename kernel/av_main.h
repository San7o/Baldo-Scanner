#ifndef _AV_MAIN_H
#define _AV_MAIN_H

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

int __init av_init(void);
void __exit av_exit(void);

#endif
