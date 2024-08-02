/* Jprobe example.
 * This module will hook the sys_open function and print the filename and the process that called it.
 *
 * Note that jprobes are depricated and should not be used in production code.
 */


#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#define MODULE_NAME "av_kernel"

MODULE_LICENSE("GPL");

/* gets called every time sys_open is called. */
static int jprobe_handler(char* filename,
                          char __user *__user *argv,
                          char __user *__user *envp,
                          struct pt_regs *regs)
{
    /* Current is a pointer to the curernt `task_struct` process. */
    printk("do_excve for %s from %s\n", filename, current->comm);
    /* Always end with a call to jprobe_return(). */
    jprobe_return();
    /* NOT REACHED */
    return 0;
}

static struct jprobe jp = {
    .entry = (kprobe_opcode_t*) jprobe_handler,
};

static int __init av_init(void)
{
    printk(KERN_INFO "AV: Module loaded\n");

    /* Register the jprobe */
    int ret;
    /* With kallsyms_lookup_name we can get the address of the sys_open function. */
    jp.kp.addr = (kprobe_opcode_t*) kallsyms_lookup_name("sys_open");
    if (!jp.kp.addr) {
        printk(KERN_ERR "AV: Could not find sys_open\n");
        return -1;
    }

    if ((ret = register_jprobe(&jp)) < 0) {
        printk("AV: register_jprobe failed, returned %d\n", ret);
        return -1;
    }
    printk("AV: Planted jprobe at %p, handler addr %p\n", jp.kp.addr, jp.entry);

    return 0;
}

static void __exit av_exit(void)
{
    unregister_jprobe(&jp);
    printk(KERN_INFO "AV: Module unloaded\n");
}

module_init(av_init);
module_exit(av_exit);
