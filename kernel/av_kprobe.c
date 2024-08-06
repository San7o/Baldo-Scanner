#include "av_kprobe.h"

int av_genl_hello(struct sk_buff *skb, struct genl_info *info) {
    printk(KERN_INFO "AV: Client HELLO\n");

    unsigned long flags;
    spin_lock_irqsave(&av_ready_lock, flags);
    send_ready = true;
    spin_unlock_irqrestore(&av_ready_lock, flags);
    return 0;
}

int av_genl_bye(struct sk_buff *skb, struct genl_info *info) {
    printk(KERN_INFO "AV: Client BYE\n");

    unsigned long flags;
    spin_lock_irqsave(&av_ready_lock, flags);
    send_ready = false;
    spin_unlock_irqrestore(&av_ready_lock, flags);
    return 0;
}

int av_genl_fetch(struct sk_buff *message_skb, struct genl_info *info) {

    printk(KERN_INFO "AV: Client FETCH\n");

    char message[MAX_STRING_SIZE];
    long unsigned int av_daemon_portid = (long unsigned int) info->snd_portid;

    unsigned long flags;
    spin_lock_irqsave(&av_data_lock, flags);
    strncpy(message, call_pathname, MAX_STRING_SIZE);
    /* Reset the call_pathname */
    call_pathname[0] = '\0';
    spin_unlock_irqrestore(&av_data_lock, flags);

    message [MAX_STRING_SIZE - 1] = '\0';

    /* 1)  Allocate a new skb */
    struct sk_buff *skb;
    skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
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
    ret = nla_put_string(skb, AV_MSG, message);
    if (ret) {
        printk(KERN_ERR "AV: Error creating message\n");
        goto error;
    }
    /* End the message */
    genlmsg_end(skb, msg_head);

    /* 3) Send the message */
    //ret = genlmsg_multicast(&av_genl_family, skb, av_daemon_portid, NETLINK_AV_GROUP, GFP_KERNEL);
    //ret = genlmsg_unicast(&init_net, skb, av_daemon_portid);
    ret = genlmsg_reply(skb, info);
    if (ret < 0) {
        printk(KERN_ERR "AV: Error sending message\n");
        goto error;
    }
    //printk(KERN_INFO "AV: Sent filename=%s\n", filename);

    return 0;
error:
    return -1;
}

int av_getname_pre_handler(struct kprobe *p, struct pt_regs *regs) {

    //printk(KERN_INFO "AV: getname called");
    //av_dump_registers(regs);
  
    spin_lock(&av_ready_lock);
    if (!send_ready) {
        spin_unlock(&av_ready_lock);
        return 0;
    }
    spin_unlock(&av_ready_lock);

    /* Get the filename */
    
    const char __user* user_filename = (const char __user*) regs_get_kernel_argument(regs, 0);
    if (!user_filename) {
        printk(KERN_ERR "AV: Error getting filename\n");
        goto error;
    }
    
    char filename[MAX_STRING_SIZE];
    // strncpy_from_user does not work :(
    unsigned long ret = raw_copy_from_user(filename, user_filename, MAX_STRING_SIZE);
    if (ret < 0) {
        printk(KERN_ERR "AV: Error copying filename\n");
        goto error;
    }
    
    char pid_c[10];
    sprintf(pid_c, "%d ", current->pid);
    spin_lock(&av_data_lock);
    strncat(call_pathname, pid_c, MAX_STRING_SIZE - strlen(call_pathname) - 1);
    strncat(call_pathname, filename, MAX_STRING_SIZE - strlen(call_pathname) - 1);
    strncat(call_pathname, "\n", MAX_STRING_SIZE - strlen(call_pathname) - 1);
    spin_unlock(&av_data_lock);
    return 0;
error:
    return -1;
}

int __init av_init(void)
{
/* Only support for x86_64 */
#ifdef __x86_64__ 
    printk(KERN_INFO "AV: Module loaded\n");

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
