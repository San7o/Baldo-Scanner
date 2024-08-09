#include "av_main.h"
#include "av_common.h"
#include "av_kprobe.h"
#include "av_netlink.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Giovanni");
MODULE_DESCRIPTION("Kprobe hook for the antivirus daemon");

int __init av_init(void)
{
/* Only support for x86_64 */
#ifdef __x86_64__ 
    printk(KERN_INFO "AV: Module loaded\n");

    kp.symbol_name = "do_sys_open";

    /* Register kprobe */
    int ret;
    if ((ret = register_kprobe(&kp)) < 0) {
        printk(KERN_INFO "AV: register_kprobe failed, returned %d\n", ret);
        return -1;
    }
    
    /* Register a family */
    ret = genl_register_family(&av_genl_family);
    if (ret) {
        printk(KERN_ERR "AV: Error registering family\n");
        return -1;
    }
#else
    printk(KERN_ERR "AV: Module not supported on this architecture\n");
#endif
    return 0;
}

static void __exit av_exit(void)
{
#ifdef __x86_64__
    unregister_kprobe(&kp);
    genl_unregister_family(&av_genl_family);
    printk(KERN_INFO "AV: Module unloaded\n");
#endif
}
