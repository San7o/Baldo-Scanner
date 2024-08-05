#include "av_kprobe.h"

int av_genl_hello(struct sk_buff *skb, struct genl_info *info) {
    printk(KERN_INFO "AV: Client HELLO\n");
    av_daemon_portid = (long unsigned int) info->snd_portid;
    av_daemon_net  = genl_info_net(info);

    char *user_filename = "Rispondone\n";
    /* Send a message using netlink */

    /* 1)  Allocate a new skb */
    struct sk_buff *skb;
    skb = nlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
    if (!skb) {
        printk(KERN_ERR "AV: Error creating skb\n");
        goto error;
    }

    /* 2) Create a new header and payload */
    int ret;
    void *msg_head;
    msg_head = genlmsg_put(skb, av_daemon_portid, 0, &av_genl_family, 0, AV_HELLO_CMD);
    if (!msg_head) {
        printk(KERN_ERR "AV: Error creating message header\n");
        goto error;
    }
    /* Add the message */
    ret = nla_put_string(skb, AV_MSG, user_filename);
    if (ret) {
        printk(KERN_ERR "AV: Error creating message\n");
        goto error;
    }
    /* End the message */
    genlmsg_end(skb, msg_head);

    /* 3) Send the message */
    //ret = genlmsg_multicast(&av_genl_family, skb, av_daemon_portid, NETLINK_AV_GROUP, GFP_KERNEL);
    ret = genlmsg_unicast(av_daemon_net, skb, av_daemon_portid);
    if (ret < 0) {
        printk(KERN_ERR "AV: Error sending message\n");
        goto error;
    }
    //printk(KERN_INFO "AV: Sent filename=%s\n", filename);
    printk(KERN_INFO "AV: Sent filename\n");




    return 0;

error:
    return -1;
}

int av_genl_bye(struct sk_buff *skb, struct genl_info *info) {
    printk(KERN_INFO "AV: Client BYE\n");
    av_daemon_portid = 0;
    return 0;
}

int av_getname_pre_handler(struct kprobe *p, struct pt_regs *regs) {

    //printk(KERN_INFO "AV: getname called");
    //av_dump_registers(regs);
    
    if (av_daemon_portid == 0) {
        //printk(KERN_ERR "AV: Daemon PID not set\n");
        return 0;
    }
    //kfree(filename);
    return 0;
error:
    //kfree(filename);
    return -1;
}

int __init av_init(void)
{
/* Only support for x86_64 */
#ifdef __x86_64__ 
    printk(KERN_INFO "AV: Module loaded\n");

    /* Setting a kprobe to the openat syscall */

    struct kprobe kp_ln = {
        .symbol_name = "kallsyms_lookup_name"
    };
    /* Get the address of kallsyms_lookup_name
     * Once the symbol_name is set, the address of the
     * probe point is determined by the kernel. So, now all
     * that's left to do is to register the probe, extract
     * the probepoint address and then unregister it*/
    /*
    register_kprobe(&kp_ln);
    kallsyms_lookup_name_t kallsyms_lookup_name = (kallsyms_lookup_name_t) kp_ln.addr;
    unregister_kprobe(&kp_ln);
    if (!kallsyms_lookup_name) {
        printk(KERN_ERR "Failed to get the address of kallsyms_lookup_name\n");
        return -1;
    }

    // Get the address of the system call table 
    unsigned long **sys_call_table = (unsigned long **) kallsyms_lookup_name("sys_call_table");
    if (!sys_call_table) {
        printk(KERN_ERR "Failed to get the address of the system call table\n");
        return -1;
    }

    // Set keyprobe
    unsigned long *syscall_openat = (unsigned long *) sys_call_table[__NR_read];
    if (!syscall_openat) {
        printk(KERN_ERR "Failed to get the address of the openat system call\n");
        return -1;
    }
    // kp.addr = (kprobe_opcode_t*) syscall_openat;
    */

    kp.symbol_name = "getname";
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
