#include <linux/module.h>   /* Needed by all modules */
#include <linux/kernel.h>   /* printk() */
#include <linux/init.h>     /* __init and __exit macros */
#include <linux/syscalls.h> /* syscall_metadata */
#include <linux/uaccess.h>  /* copy_to_user */
#include <linux/kallsyms.h> /* kallsyms_lookup_name */
#include <linux/kprobes.h>  /* kprobe */

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
asmlinkage long (*original_syscall_open)(const char __user*, int, umode_t);

/* Define the kallsyms_lookup_name call */
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);

static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};

/* Define the new hooked open system call */
asmlinkage long hooked_open(const char __user* filename, int flags, umode_t mode) {
     printk(KERN_INFO "Hooked open system call\n");

     /* Call the original open system call */
     return original_syscall_open(filename, flags, mode);
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
    write_cr0(read_cr0() & (~0x10000));
#elif defined(__arm__)
    unsigned int sctlr;
    asm volatile("MRC p15, 0, %0, c1, c0, 0" : "=r" (sctlr));
    sctlr &= ~(1 << 16); // Clear the WP bit (bit 16)
    asm volatile("MCR p15, 0, %0, c1, c0, 0" : : "r" (sctlr));
#elif defined(__aarch64__)
    unsigned long sctlr_el1;
    asm volatile("MRS %0, SCTLR_EL1" : "=r" (sctlr_el1));
    sctlr_el1 &= ~(1 << 16); // Clear the WP bit (bit 16)
    asm volatile("MSR SCTLR_EL1, %0" : : "r" (sctlr_el1));
#else
#error "Unsupported architecture"
#endif
}

static void enable_write_protection(void) {
#if defined(__x86_64__)
    write_cr0(read_cr0() | 0x10000);
#elif defined(__arm__)
    unsigned int sctlr;
    asm volatile("MRC p15, 0, %0, c1, c0, 0" : "=r" (sctlr));
    sctlr |= (1 << 16); // Set the WP bit (bit 16)
    asm volatile("MCR p15, 0, %0, c1, c0, 0" : : "r" (sctlr));
#elif defined(__aarch64__)
    unsigned long sctlr_el1;
    asm volatile("MRS %0, SCTLR_EL1" : "=r" (sctlr_el1));
    sctlr_el1 |= (1 << 16); // Set the WP bit (bit 16)
    asm volatile("MSR SCTLR_EL1, %0" : : "r" (sctlr_el1));
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
    kallsyms_lookup_name_t kallsyms_lookup_name;
    register_kprobe(&kp);
    kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
    unregister_kprobe(&kp);

    /* Get the address of the system call table */
    sys_call_table = (unsigned long **) kallsyms_lookup_name("sys_call_table");

    disable_write_protection();

    /* __NR_open is the index of the open system call
     * It is defined in /usr/include/asm/unistd_64.h (similare for 32-bit)
     */
    original_syscall_open = (void *) sys_call_table[__NR_open];

    sys_call_table[__NR_open] = (unsigned long *) hooked_open;

    enable_write_protection();

    return 0;
}

static void __exit hook_exit(void) {

    printk(KERN_INFO "Unhooking system call table\n");
    disable_write_protection();

    sys_call_table[__NR_open] = (unsigned long *) original_syscall_open;

    enable_write_protection();
}

module_init(hook_init);
module_exit(hook_exit);


