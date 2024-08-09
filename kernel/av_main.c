#include "av_main.h"
#include "av_common.h"
#include "av_kprobe.h"
#include "av_netlink.h"
#include "av_firewall.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Giovanni");
MODULE_DESCRIPTION("Kprobe hook for the antivirus daemon");

int __init av_init(void)
{
/* Only support for x86_64 */
#ifdef __x86_64__ 

    /* Register kprobe */
    int ret;
    kp.symbol_name = "do_sys_open";
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

    /* Register net hook */
    nf_register_net_hook(&init_net, &hook_ops);

    printk(KERN_INFO "AV: Module loaded\n");
#else
    printk(KERN_ERR "AV: Module not supported on this architecture\n");
#endif
    return 0;
}

void __exit av_exit(void)
{
#ifdef __x86_64__
    unregister_kprobe(&kp);
    genl_unregister_family(&av_genl_family);
    nf_unregister_net_hook(&init_net, &hook_ops);

    /* Remove all entries from the hashtable */
    struct ip_entry *entry;
    int bkt;
    hash_for_each_rcu(av_blocked, bkt, entry, node) {
        hash_del_rcu(&entry->node);
        kfree(entry);
    }

    printk(KERN_INFO "AV: Module unloaded\n");
#endif
}

module_init(av_init);
module_exit(av_exit);
