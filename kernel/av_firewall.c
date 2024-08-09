#include "av_firewall.h"

DEFINE_READ_MOSTLY_HASHTABLE(av_blocked, AV_HASH_BITS);

/*
 * Hooknum:
 * - NF_INET_PRE_ROUTING: For packets arriving at the network interface.
 * - NF_INET_LOCAL_IN: For packets destined for the local machine.
 * - NF_INET_FORWARD: For packets being forwarded to another interface.
 * - NF_INET_LOCAL_OUT: For packets being sent by the local machine.
 * - NF_INET_POST_ROUTING: For packets leaving the network interface.
 */
struct nf_hook_ops hook_ops =
{
    .hook = av_nf_hook,
    .pf = PF_INET,                  /* Ipv4 */
    .hooknum = NF_INET_LOCAL_IN,    /* Hook at re routing stage */
    .priority = NF_IP_PRI_FIRST,    /* Highest priority */
};

bool av_is_blocked(__be32 ip)
{
    struct ip_entry *entry;
    printk(KERN_INFO "AV: Checking if %u is blocked\n", ip);
    hash_for_each_possible_rcu(av_blocked, entry, node, ip)
    {
        if (entry->ip == ip)
        {
            return true;
        }
    }
    return false;
}

unsigned int av_nf_hook(void* priv, struct sk_buff* skb, const struct nf_hook_state* state)
{
    struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);

    /* Check if the packet is TCP */
    if (ip_header->protocol != IPPROTO_TCP)
    {
        return NF_ACCEPT;
    }

    /* Check if the packet address is in the blocked list */
    if (av_is_blocked(ip_header->saddr))
    {
        printk(KERN_INFO "AV: Blocked packet from %pI4\n", &ip_header->saddr);
        return NF_DROP;
    }

    return NF_ACCEPT;
}

MODULE_LICENSE("GPL");
