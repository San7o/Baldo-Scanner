// SPDX-License-Identifier: GPL-2.0+
// Author:  Giovanni Santini
// Mail:    giovanni.santini@proton.me
// Github:  @San7o

#include "main.h"
#include "common.h"
#include "kprobe.h"
#include "firewall.h"

#ifdef BALDO_CHAR_DEV
#include "char_dev.h"
#endif

#ifdef BALDO_NETLINK
#include "netlink.h"
#endif

#include <linux/version.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Giovanni Santini");
MODULE_DESCRIPTION("Kprobe hook and firewall module");

int __init baldo_init(void)
{
  /* Initialize the data buff */
  unsigned long flags;
  spin_lock_irqsave(&baldo_data_lock, flags);
  call_data_buffer = kmalloc(sizeof(struct call_data_buffer_s), GFP_KERNEL);
  call_data_buffer->num = 0;
  spin_unlock_irqrestore(&baldo_data_lock, flags);

  /* Register kprobe */
  int ret;
  kp.symbol_name = "do_sys_open";
  if ((ret = register_kprobe(&kp)) < 0)
  {
    kfree(call_data_buffer);
    printk(KERN_INFO "Baldo: register_kprobe failed, returned %d\n", ret);
    return -1;
  }

#ifdef BALDO_CHAR_DEV
  /* Dynamic allocation */
  if (alloc_chrdev_region(&baldo_dev, 0, 3, (const char *) MODULE_NAME) < 0)
  {
    printk(KERN_ERR "alloc_chrdev_region failed\n");
    kfree(call_data_buffer);
    unregister_kprobe(&kp);
    return -1;
  }
  printk(KERN_INFO "Registered character device with major: %d\n", MAJOR(baldo_dev));

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0)
  baldo_cdev_class = class_create((const char *) MODULE_NAME);
#else
  baldo_cdev_class = class_create(THIS_MODULE, (const char *) MODULE_NAME);
#endif
  if (!baldo_cdev_class)
  {
    printk(KERN_ERR "class_create failed\n");
    kfree(call_data_buffer);
    unregister_kprobe(&kp);
    unregister_chrdev_region(baldo_dev, 1);
    return -1;
  }
  /* Notify device */
  cdev_init(&baldo_notify_cdev, &baldo_notify_ops);
  if (cdev_add(&baldo_notify_cdev, MKDEV(MAJOR(baldo_dev), 1), 1) < 0)
  {
    printk(KERN_ERR "cdev_add notify failed\n");
    kfree(call_data_buffer);
    unregister_kprobe(&kp);
    unregister_chrdev_region(baldo_dev, 1);
    return -1;
  }
  /* Firewall device */
  cdev_init(&baldo_firewall_cdev, &baldo_firewall_ops);
  if (cdev_add(&baldo_firewall_cdev, MKDEV(MAJOR(baldo_dev), 2), 1) < 0)
  {
    printk(KERN_ERR "cdev_add notify failed\n");
    kfree(call_data_buffer);
    unregister_kprobe(&kp);
    class_unregister(baldo_cdev_class);
    cdev_del(&baldo_notify_cdev);
    unregister_chrdev_region(baldo_dev, 1);
    return -1;
  }
  /* Create devices */
  if (!device_create(baldo_cdev_class, NULL,
                     MKDEV(MAJOR(baldo_dev), BALDO_NOTIFY_MINOR), NULL,
                     (const char *) BALDO_DEV_NOTIFY_NAME))
  {
    printk(KERN_ERR "device_create failed\n");
    kfree(call_data_buffer);
    unregister_kprobe(&kp);
    class_unregister(baldo_cdev_class);
    cdev_del(&baldo_notify_cdev);
    cdev_del(&baldo_firewall_cdev);
    unregister_chrdev_region(baldo_dev, 1);
    return -1;
  }
  if (!device_create(baldo_cdev_class, NULL,
                     MKDEV(MAJOR(baldo_dev), BALDO_FIREWALL_MINOR), NULL,
                     (const char *) BALDO_DEV_FIREWALL_NAME))
  {
    printk(KERN_ERR "device_create failed\n");
    kfree(call_data_buffer);
    unregister_kprobe(&kp);
    device_destroy(baldo_cdev_class, MKDEV(MAJOR(baldo_dev), 1));
    class_unregister(baldo_cdev_class);
    cdev_del(&baldo_notify_cdev);
    cdev_del(&baldo_firewall_cdev);
    unregister_chrdev_region(baldo_dev, 1);
    return -1;
  }
#endif

#ifdef BALDO_NETLINK
  /* Register a family */
  ret = genl_register_family(&baldo_genl_family);
  if (ret != 0)
  {
    printk(KERN_ERR "Baldo: Error registering family\n");
    kfree(call_data_buffer);
    unregister_kprobe(&kp);
#ifdef BALDO_CHAR_DEV
    device_destroy(baldo_cdev_class, MKDEV(MAJOR(baldo_dev), 1));
    class_unregister(baldo_cdev_class);
    cdev_del(&baldo_notify_cdev);
    cdev_del(&baldo_firewall_cdev);
    unregister_chrdev_region(baldo_dev, 1);
#endif
    return -1;
  }
#endif
  /* Register net hook */
  nf_register_net_hook(&init_net, &hook_ops);

  printk(KERN_INFO "Baldo: Module loaded\n");
  return 0;
}

void __exit baldo_exit(void)
{
  unregister_kprobe(&kp);
#ifdef BALDO_NETLINK
  genl_unregister_family(&baldo_genl_family);
#endif
#ifdef BALDO_CHAR_DEV
  device_destroy(baldo_cdev_class, MKDEV(MAJOR(baldo_dev), 1));
  device_destroy(baldo_cdev_class, MKDEV(MAJOR(baldo_dev), 2));
  class_unregister(baldo_cdev_class);
  cdev_del(&baldo_notify_cdev);
  cdev_del(&baldo_firewall_cdev);
  unregister_chrdev_region(baldo_dev, 1);
#endif
  nf_unregister_net_hook(&init_net, &hook_ops);

  /* Remove all entries from the hashtable */
  struct ip_entry *entry;
  int bkt;
  hash_for_each_rcu(baldo_blocked, bkt, entry, node)
  {
    hash_del_rcu(&entry->node);
    kfree(entry);
  }

  kfree(call_data_buffer);

  printk(KERN_INFO "Baldo: Module unloaded\n");
}

module_init(baldo_init);
module_exit(baldo_exit);
