#ifndef _AV_FIREWALL_H
#define _AV_FIREWALL_H

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/hashtable.h>

#define AV_HASH_BITS 8

/* structure definitions */

struct ip_entry
{
    struct hlist_node node;
    __be32 ip;
};

extern struct nf_hook_ops hook_ops;

extern DECLARE_HASHTABLE(av_blocked, AV_HASH_BITS) __read_mostly;

/* function prototypes */

unsigned int av_nf_hook(void* priv, struct sk_buff* skb, const struct nf_hook_state* state);
bool av_is_blocked(__be32 ip);

#endif
