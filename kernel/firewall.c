// SPDX-License-Identifier: GPL-2.0+
// Author:  Giovanni Santini
// Mail:    giovanni.santini@proton.me
// Github:  @San7o

#include "firewall.h"

DEFINE_READ_MOSTLY_HASHTABLE(baldo_blocked, BALDO_HASH_BITS);

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
  .hook = baldo_nf_hook,
  .pf = PF_INET,                  /* Ipv4 */
  .hooknum = NF_INET_LOCAL_IN,    /* Hook at re routing stage */
  .priority = NF_IP_PRI_FIRST,    /* Highest priority */
};

bool baldo_is_blocked(__be32 ip)
{
  struct ip_entry *entry;
  printk(KERN_INFO "Baldo: Checking if %u is blocked\n", ip);
  hash_for_each_possible_rcu(baldo_blocked, entry, node, ip)
  {
    if (entry->ip == ip)
      {
        return true;
      }
  }
  return false;
}

unsigned int baldo_nf_hook(void* priv, struct sk_buff* skb,
                           const struct nf_hook_state* state)
{
  struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);

  /* Check if the packet is TCP */
  if (ip_header->protocol != IPPROTO_TCP)
  {
    return NF_ACCEPT;
  }

  /* Check if the packet address is in the blocked list */
  if (baldo_is_blocked(ip_header->saddr))
  {
    printk(KERN_INFO "Baldo: Blocked packet from %pI4\n", &ip_header->saddr);
    return NF_DROP;
  }

  return NF_ACCEPT;
}

MODULE_LICENSE("GPL");
