#ifndef AV_KPROBE_H
#define AV_KPROBE_H

/* Kernel headers */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/uaccess.h>     /* copy_from_user */
#include <linux/slab.h>        /* kmalloc */
#include <uapi/asm/ptrace.h>   /* pt_regs for i386 */
#include <linux/kallsyms.h>    /* kallsyms_lookup_name */

/* Kprobe headers */
#include <linux/kprobes.h>

/* Netlink headers */
#include <linux/netlink.h>     /* netlink_kernel_create, netlink_kernel_release */
#include <net/genetlink.h>     /* genl_register_family */
#include <net/netlink.h>       /* nla_put_string */

#define MODULE_NAME "av_kprobe"
#define NETLINK_AV_GROUP 31
#define MAX_STRING_SIZE 1024
#define AV_FAMILY_NAME "AV_GENL"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Giovanni");
MODULE_DESCRIPTION("Kprobe hook for the antivirus daemon");

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);

/* The port ID of the antivirus daemon */
static unsigned int av_daemon_portid = 0;
static struct net *av_daemon_net = NULL;

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

/* Operation Commands */
enum {
    AV_UNSPEC_CMD,
    AV_HELLO_CMD,   /* hello command,  requests connection */
    AV_BYE_CMD,     /* bye command,    close connection */
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
};

/* Debug function */
/*
static void av_dump_registers(struct pt_regs *regs) {
    //dump_stack();
    printk(KERN_INFO "AV: ===== Registers =====\n");
    printk(KERN_INFO "AV: rax=0x%lx\n", regs->ax);
    printk(KERN_INFO "AV: rbx=0x%lx\n", regs->bx);
    printk(KERN_INFO "AV: rcx=0x%lx\n", regs->cx);
    printk(KERN_INFO "AV: rdx=0x%lx\n", regs->dx);
    printk(KERN_INFO "AV: rbp=0x%lx\n", regs->bp);
    printk(KERN_INFO "AV: rdi=0x%lx\n", regs->di);
    printk(KERN_INFO "AV: rsi=0x%lx\n", regs->si);
    printk(KERN_INFO "AV: r10=0x%lx\n", regs->r10);
    printk(KERN_INFO "AV: r8=0x%lx\n", regs->r8);
    printk(KERN_INFO "AV: r9=0x%lx\n", regs->r9);
    unsigned long arg1 = regs_get_kernel_argument(regs, 0);
    unsigned long arg2 = regs_get_kernel_argument(regs, 1);
    unsigned long arg3 = regs_get_kernel_argument(regs, 2);
    unsigned long arg4 = regs_get_kernel_argument(regs, 3);
    printk(KERN_INFO "AV: arg1=0x%lx\n", arg1);
    printk(KERN_INFO "AV: arg2=0x%lx\n", arg2);
    printk(KERN_INFO "AV: arg3=0x%lx\n", arg3);
    printk(KERN_INFO "AV: arg4=0x%lx\n", arg4);
}
*/

/* 
 * arch/x86/enty/calling.h
 * x86 function call convention, 64-bit:
 * -------------------------------------
 *  arguments           |  callee-saved      | extra caller-saved | return
 * [callee-clobbered]   |                    | [callee-clobbered] |
 * ---------------------------------------------------------------------------
 * rdi rsi rdx rcx r8-9 | rbx rbp [*] r12-15 | r10-11             | rax, rdx [**]
 *
 * This function gets called when the kprobe is hit.
 *
 * `pt_regs` is defined based on your architecture
 * x86 is defined in "arch/x86/include/asm/ptrace.h".
 * Registers use the 16 bits of the 64-bit register.
 */
int av_getname_pre_handler(struct kprobe *p, struct pt_regs *regs);

/* 
 * Symbol names are found in System.map 
 * linux/kprobes.h
 */
static struct kprobe kp = {
    .pre_handler = av_getname_pre_handler,
};

static int __init av_init(void);
static void __exit av_exit(void);

module_init(av_init);
module_exit(av_exit);

#endif
