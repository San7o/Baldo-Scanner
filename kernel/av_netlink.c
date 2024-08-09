#include "av_netlink.h"
#include "av_common.h"

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
    if (call_pathname[0] == '\0') {
        spin_unlock_irqrestore(&av_data_lock, flags);
        return 0;
    }
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

MODULE_LICENSE("GPL");
