#ifdef AV_NETLINK

#include "av_netlink.h"
#include "av_firewall.h"
#include "av_common.h"

#include <linux/hashtable.h>

struct nla_policy av_genl_policy[AV_MAX + 1] =
{
    [AV_MSG]  = { .type = NLA_NUL_STRING },  /* Null terminated strings */
    [AV_IPv4] = { .type = NLA_U32 },        /* 32-bit unsigned integers */
};

struct genl_ops av_genl_ops[] =
{
    {
        .cmd = AV_HELLO_CMD,
        .flags = 0,
        .policy = av_genl_policy,
        .doit = av_genl_hello,
        .dumpit = NULL,
    },
    {
        .cmd = AV_BYE_CMD,
        .flags = 0,
        .policy = av_genl_policy,
        .doit = av_genl_bye,
        .dumpit = NULL,
    },
    {
        .cmd = AV_FETCH_CMD,
        .flags = 0,
        .policy = av_genl_policy,
        .doit = av_genl_fetch,
        .dumpit = NULL,
    },
    {
        .cmd = AV_BLOCK_IP_CMD,
        .flags = 0,
        .policy = av_genl_policy,
        .doit = av_genl_block_ip,
        .dumpit = NULL,
    },
    {
        .cmd = AV_UNBLOCK_IP_CMD,
        .flags = 0,
        .policy = av_genl_policy,
        .doit = av_genl_unblock_ip,
        .dumpit = NULL,
    },
};

struct genl_family av_genl_family =
{
    .id = 0,           /* Automatic ID generation */
    .hdrsize = 0,
    .name = AV_FAMILY_NAME,
    .version = 1,
    .maxattr = AV_MAX,
    .ops = av_genl_ops,
    .n_ops = ARRAY_SIZE(av_genl_ops),
    .parallel_ops = 0,
};

int av_genl_hello(struct sk_buff *skb, struct genl_info *info)
{
    printk(KERN_INFO "AV: Client HELLO\n");

    unsigned long flags;
    spin_lock_irqsave(&av_ready_lock, flags);
    send_ready = true;
    spin_unlock_irqrestore(&av_ready_lock, flags);
    return 0;
}

int av_genl_bye(struct sk_buff *skb, struct genl_info *info)
{
    printk(KERN_INFO "AV: Client BYE\n");

    unsigned long flags;
    spin_lock_irqsave(&av_ready_lock, flags);
    send_ready = false;
    spin_unlock_irqrestore(&av_ready_lock, flags);
    return 0;
}

int av_genl_fetch(struct sk_buff *message_skb, struct genl_info *info)
{
    //printk(KERN_INFO "AV: Client FETCH\n");

    char message[MAX_STRING_SIZE];
    long unsigned int av_daemon_portid = (long unsigned int) info->snd_portid;

    unsigned long flags;
    spin_lock_irqsave(&av_data_lock, flags);
    if (call_pathname[0] == '\0')
    {
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
    if (!skb)
    {
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
    if (ret)
    {
        printk(KERN_ERR "AV: Error creating message\n");
        goto error;
    }
    /* End the message */
    genlmsg_end(skb, msg_head);

    /* 3) Send the message */
    //ret = genlmsg_multicast(&av_genl_family, skb, av_daemon_portid, NETLINK_AV_GROUP, GFP_KERNEL);
    //ret = genlmsg_unicast(&init_net, skb, av_daemon_portid);
    ret = genlmsg_reply(skb, info);
    if (ret < 0)
    {
        printk(KERN_ERR "AV: Error sending message\n");
        goto error;
    }
    //printk(KERN_INFO "AV: Sent filename=%s\n", filename);

    return 0;
error:
    return -1;
}

int av_genl_block_ip(struct sk_buff *message, struct genl_info *info)
{
    if (info->attrs[AV_IPv4])
    {
        __be32 ip = nla_get_u32(info->attrs[AV_IPv4]);
        struct ip_entry *entry;
        entry = kmalloc(sizeof(struct ip_entry), GFP_KERNEL);
        if (!entry) {
            printk(KERN_ERR "AV: Error allocating memory\n");
            return -1;
        }
        entry->ip = ip;
        hash_add_rcu(av_blocked, &entry->node, ip);
        printk(KERN_INFO "AV: Added IP %p to the blocked list\n", &ip);
        return 0;
    }

    printk(KERN_ERR "AV: No IP address provided\n");
    return -1;
}

int av_genl_unblock_ip(struct sk_buff *message, struct genl_info *info)
{
    if (info->attrs[AV_IPv4])
    {
        __be32 ip = nla_get_u32(info->attrs[AV_IPv4]);
        struct ip_entry *entry;

        hash_for_each_possible_rcu(av_blocked, entry, node, ip)
        {
            if (entry->ip == ip)
            {
                hash_del_rcu(&entry->node);
                kfree(entry);
                printk(KERN_INFO "AV: Removed IP %p from the blocked list\n", &ip);
                return 0;
            }
        }

        return 0;
    }

    printk(KERN_ERR "AV: No IP address provided\n");
    return -1;
}

MODULE_LICENSE("GPL");

#endif // AV_NETLINK
