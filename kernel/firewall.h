// SPDX-License-Identifier: GPL-2.0+
// Author:  Giovanni Santini
// Mail:    giovanni.santini@proton.me
// Github:  @San7o

#ifndef _BALDO_FIREWALL_H
#define _BALDO_FIREWALL_H

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/hashtable.h>

#define BALDO_HASH_BITS 8

/* structure definitions */

struct ip_entry {
  struct hlist_node node;
  __be32 ip;
};

extern struct nf_hook_ops hook_ops;

extern DECLARE_HASHTABLE(baldo_blocked, BALDO_HASH_BITS) __read_mostly;

/* function prototypes */

unsigned int baldo_nf_hook(void* priv, struct sk_buff* skb,
                           const struct nf_hook_state* state);
bool baldo_is_blocked(__be32 ip);

#endif // _BALDO_FIREWALL_H
