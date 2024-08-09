/*
 *   NOTE: This method does not work anymore on newer kernels.
 *   This file is kept for reference purposes only.
 */

#include <linux/module.h>   /* Needed by all modules */
#include <linux/kernel.h>   /* printk() */
#include <linux/init.h>     /* __init and __exit macros */
#include <linux/syscalls.h> /* syscall_metadata */
#include <linux/uaccess.h>  /* copy_to_user */
#include <linux/kallsyms.h> /* kallsyms_lookup_name */
#include <linux/kprobes.h>  /* kprobe */
#include <linux/types.h>    /* umode_t */
#include <asm/paravirt.h>   /* write_cr0, read_cr0 */

#define MODULE_NAME "systable_hook"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Giovanni");
MODULE_DESCRIPTION("System call table hooking");

/* Define the system call table */
static unsigned long **sys_call_table;

/* Define the prototype of the original open system call
 * `asmlinkage` tells the compiler that the function
 * should not expect to find any of its arguments in
 * registers (a common optimization), but only on the CPU's stack.
 * All system calls are marked with this. */
asmlinkage long (*original_syscall_openat)(int, const char __user*, int flags, umode_t mode);

/* Define the kallsyms_lookup_name call */
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);

static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};

asmlinkage long hooked_openat(int dfd, const char __user* filename, int flags, umode_t mode) {
    printk(KERN_INFO "Hooked openat system call\n");

    /* Call the original open system call */
    return original_syscall_openat(dfd, filename, flags, mode);
}


static unsigned long __force_order;
static inline void wr_cr0(unsigned long val) {
    asm volatile("mov %0, %%cr0": "+r" (val), "+m"(__force_order));
}

static void disable_write_protection(void) {
#if defined(__x86_64__)
    /*
     * Control Register 0 (CR0) Bit 16 (WP) Write Protect (R/W)
     *
     * read_cr0 is a macro that reads the CR0 register and returns it.
     *         This register is a 32-bit register that controls various
     *         flags for the x86 CPU.
     * 0x10000 is the bit mask for the WP bit. My performing and AND
     *        operation with the complement of this value, we are
     *        clearing the WP bit.
     *        Example:
     *        >>> bin(0x10000)
     *        >>> '0b10000000000000000'
     */
    //wr_cr0(read_cr0() & (~0x10000));
    unsigned long cr0 = read_cr0();
    clear_bit(16, &cr0);
    wr_cr0(cr0);
#else
#error "Unsupported architecture"
#endif
}

static void enable_write_protection(void) {
#if defined(__x86_64__)
    //write_cr0(read_cr0() | 0x10000);
    unsigned long cr0 = read_cr0();
    set_bit(16, &cr0);
    wr_cr0(cr0);
#else
#error "Unsupported architecture"
#endif
}

static int __init hook_init(void) {

    printk(KERN_INFO "Hooking system call table\n");

    /* get the address of the kallsyms_lookup_name function
     * Once the symbol_name is set, the address of the
     * probe point is determined by the kernel. So, now all
     * that's left to do is to register the probe, extract
     * the probepoint address and then unregister it*/
    register_kprobe(&kp);
    kallsyms_lookup_name_t kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
    unregister_kprobe(&kp);
    if (!kallsyms_lookup_name) {
        printk(KERN_ERR "Failed to get the address of kallsyms_lookup_name\n");
        return -1;
    }

    /* Get the address of the system call table */
    sys_call_table = (unsigned long **) kallsyms_lookup_name("sys_call_table");
    if (!sys_call_table) {
        printk(KERN_ERR "Failed to get the address of the system call table\n");
        return -1;
    }

    /* __NR_open is the index of the open system call */
    original_syscall_openat = (void *) sys_call_table[257];

    printk(KERN_INFO "Original openat system call: %p\n", original_syscall_openat);
    printk(KERN_INFO "Hooked openat system call: %p\n", hooked_openat);

    disable_write_protection();
    sys_call_table[257] = (void *) hooked_openat;
    enable_write_protection();

    printk(KERN_INFO "sys_call_table 257: %p\n", sys_call_table[257]);

    return 0;
}

static void __exit hook_exit(void) {

    printk(KERN_INFO "Unhooking system call table\n");

    disable_write_protection();
    sys_call_table[257] = (unsigned long *) original_syscall_openat;
    enable_write_protection();
}

module_init(hook_init);
module_exit(hook_exit);
