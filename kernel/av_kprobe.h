#ifndef _AV_KPROBE_H
#define _AV_KPROBE_H

/* Kernel headers */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/uaccess.h>     /* copy_from_user */
#include <linux/slab.h>        /* kmalloc */
#include <uapi/asm/ptrace.h>   /* pt_regs for i386 */
#include <linux/kallsyms.h>    /* kallsyms_lookup_name */
#include <linux/spinlock.h>    /* spinlocks */
#include <linux/string.h>

/* Kprobe headers */
#include <linux/kprobes.h>

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
extern struct kprobe kp;

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

#endif
