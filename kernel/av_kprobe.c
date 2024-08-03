/* Kprobe example.
 * This module will hook the sys_open function and print the filename and the process that called it.
 *
 * Note that kprobes are depricated and should not be used in production code.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#define MODULE_NAME "av_kprobe"

MODULE_LICENSE("GPL");

int av_pre_handler(struct kretprobe_instance *p, struct pt_regs *regs) {
    printk(KERN_INFO "AV: openat called");
    return 0;
}

int av_post_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    printk(KERN_INFO "AV: openat returned");
    return 0;
}

/* Symbol names are found in System.map */
static struct kretprobe kp_ret = {
    .handler = av_post_handler,
    .entry_handler = av_pre_handler,
    .kp = {
        .symbol_name = "generic_file_open",
    },
};

static int __init av_init(void)
{
    printk(KERN_INFO "AV: Module loaded\n");

    int ret;
    if ((ret = register_kretprobe(&kp_ret)) < 0) {
        printk(KERN_INFO "AV: register_kprobe failed, returned %d\n", ret);
        return -1;
    }

    return 0;
}

static void __exit av_exit(void)
{
    unregister_kretprobe(&kp_ret);
    printk(KERN_INFO "AV: Module unloaded\n");
}

module_init(av_init);
module_exit(av_exit);
