#include "av_main.h"
#include "av_common.h"
#include "av_kprobe.h"
#include "av_firewall.h"

#ifdef AV_CHAR_DEV
#include "av_char_dev.h"
#endif

#ifdef AV_NETLINK
#include "av_netlink.h"
#endif

#include <linux/version.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Giovanni");
MODULE_DESCRIPTION("Kprobe hook for the antivirus daemon");

int __init av_init(void)
{
    /* Register kprobe */
    int ret;
    kp.symbol_name = "do_sys_open";
    if ((ret = register_kprobe(&kp)) < 0)
    {
        printk(KERN_INFO "AV: register_kprobe failed, returned %d\n", ret);
        return -1;
    }

#ifdef AV_NETLINK
    /* Register a family */
    ret = genl_register_family(&av_genl_family);
    if (ret != 0)
    {
        printk(KERN_ERR "AV: Error registering family\n");
        unregister_kprobe(&kp);
        return -1;
    }
#endif

#ifdef AV_CHAR_DEV
    /* Dynamic allocation */
    if (alloc_chrdev_region(&av_dev, 0, 3, (const char *) MODULE_NAME) < 0)
    {
        printk(KERN_ERR "alloc_chrdev_region failed\n");
        unregister_kprobe(&kp);
        return -1;
    }
    printk(KERN_INFO "Registered character device with major: %d\n", MAJOR(av_dev));

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0)
    av_cdev_class = class_create((const char *) MODULE_NAME);
#else
    av_cdev_class = class_create(THIS_MODULE, (const char *) MODULE_NAME);
#endif
    if (!av_cdev_class)
    {
        printk(KERN_ERR "class_create failed\n");
        unregister_kprobe(&kp);
        unregister_chrdev_region(av_dev, 1);
        return -1;
    }
    /* Notify device */
    cdev_init(&av_notify_cdev, &av_notify_ops);
    if (cdev_add(&av_notify_cdev, MKDEV(MAJOR(av_dev), 1), 1) < 0)
    {
        printk(KERN_ERR "cdev_add notify failed\n");
        unregister_kprobe(&kp);
        unregister_chrdev_region(av_dev, 1);
        return -1;
    }
    /* Firewall device */
    cdev_init(&av_firewall_cdev, &av_firewall_ops);
    if (cdev_add(&av_firewall_cdev, MKDEV(MAJOR(av_dev), 2), 1) < 0)
    {
        printk(KERN_ERR "cdev_add notify failed\n");
        unregister_kprobe(&kp);
        class_unregister(av_cdev_class);
        cdev_del(&av_notify_cdev);
        unregister_chrdev_region(av_dev, 1);
        return -1;
    }
    /* Create devices */
    if (!device_create(av_cdev_class, NULL, MKDEV(MAJOR(av_dev), AV_NOTIFY_MINOR), NULL,
                            (const char *) AV_DEV_NOTIFY_NAME))
    {
        printk(KERN_ERR "device_create failed\n");
        unregister_kprobe(&kp);
        class_unregister(av_cdev_class);
        cdev_del(&av_notify_cdev);
        cdev_del(&av_firewall_cdev);
        unregister_chrdev_region(av_dev, 1);
        return -1;
    }
    if (!device_create(av_cdev_class, NULL, MKDEV(MAJOR(av_dev), AV_FIREWALL_MINOR), NULL,
                            (const char *) AV_DEV_FIREWALL_NAME))
    {
        printk(KERN_ERR "device_create failed\n");
        unregister_kprobe(&kp);
        device_destroy(av_cdev_class, MKDEV(MAJOR(av_dev), 1));
        class_unregister(av_cdev_class);
        cdev_del(&av_notify_cdev);
        cdev_del(&av_firewall_cdev);
        unregister_chrdev_region(av_dev, 1);
        return -1;
    }
#endif
    /* Register net hook */
    nf_register_net_hook(&init_net, &hook_ops);

    printk(KERN_INFO "AV: Module loaded\n");
    return 0;
}

void __exit av_exit(void)
{
    unregister_kprobe(&kp);
#ifdef AV_NETLINK
    genl_unregister_family(&av_genl_family);
#endif
#ifdef AV_CHAR_DEV
    device_destroy(av_cdev_class, MKDEV(MAJOR(av_dev), 1));
    device_destroy(av_cdev_class, MKDEV(MAJOR(av_dev), 2));
    class_unregister(av_cdev_class);
    cdev_del(&av_notify_cdev);
    cdev_del(&av_firewall_cdev);
    unregister_chrdev_region(av_dev, 1);
#endif
    nf_unregister_net_hook(&init_net, &hook_ops);

    /* Remove all entries from the hashtable */
    struct ip_entry *entry;
    int bkt;
    hash_for_each_rcu(av_blocked, bkt, entry, node)
    {
        hash_del_rcu(&entry->node);
        kfree(entry);
    }

    printk(KERN_INFO "AV: Module unloaded\n");
}

module_init(av_init);
module_exit(av_exit);
