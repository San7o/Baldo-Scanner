// SPDX-License-Identifier: GPL-2.0+
// Author:  Giovanni Santini
// Mail:    giovanni.santini@proton.me
// Github:  @San7o

#ifdef BALDO_NETLINK

#include "netlink.h"
#include "firewall.h"
#include "common.h"

#include <linux/hashtable.h>

struct nla_policy baldo_genl_policy[BALDO_MAX + 1] =
{
  [BALDO_MSG]  = { .type = NLA_NUL_STRING },  /* Null terminated strings */
  [BALDO_IPv4] = { .type = NLA_U32 },         /* 32-bit unsigned integers */
  [BALDO_DATA] = { .type = NLA_BINARY },      /* Binary data */
};

struct genl_ops baldo_genl_ops[] =
{
  {
    .cmd = BALDO_HELLO_CMD,
    .flags = 0,
    .policy = baldo_genl_policy,
    .doit = baldo_genl_hello,
    .dumpit = NULL,
  },
  {
    .cmd = BALDO_BYE_CMD,
    .flags = 0,
    .policy = baldo_genl_policy,
    .doit = baldo_genl_bye,
    .dumpit = NULL,
  },
  {
    .cmd = BALDO_FETCH_CMD,
    .flags = 0,
    .policy = baldo_genl_policy,
    .doit = baldo_genl_fetch,
    .dumpit = NULL,
  },
  {
    .cmd = BALDO_BLOCK_IP_CMD,
    .flags = 0,
    .policy = baldo_genl_policy,
    .doit = baldo_genl_block_ip,
    .dumpit = NULL,
  },
  {
    .cmd = BALDO_UNBLOCK_IP_CMD,
    .flags = 0,
    .policy = baldo_genl_policy,
    .doit = baldo_genl_unblock_ip,
    .dumpit = NULL,
  },
};

struct genl_family baldo_genl_family =
{
  .id = 0,           /* Automatic ID generation */
  .hdrsize = 0,
  .name = BALDO_FAMILY_NAME,
  .version = 1,
  .maxattr = BALDO_MAX,
  .ops = baldo_genl_ops,
  .n_ops = ARRAY_SIZE(baldo_genl_ops),
  .parallel_ops = 0,
};

int baldo_genl_hello(struct sk_buff *skb, struct genl_info *info)
{
  printk(KERN_INFO "Baldo: Client HELLO\n");

  unsigned long flags;
  spin_lock_irqsave(&baldo_ready_lock, flags);
  send_ready = true;
  spin_unlock_irqrestore(&baldo_ready_lock, flags);
  return 0;
}

int baldo_genl_bye(struct sk_buff *skb, struct genl_info *info)
{
  printk(KERN_INFO "Baldo: Client BYE\n");

  unsigned long flags;
  spin_lock_irqsave(&baldo_ready_lock, flags);
  send_ready = false;
  spin_unlock_irqrestore(&baldo_ready_lock, flags);
  return 0;
}

int baldo_genl_fetch(struct sk_buff *message_skb, struct genl_info *info)
{
  //printk(KERN_INFO "Baldo: Client FETCH\n");

  spin_lock(&baldo_ready_lock);
  if (!send_ready)
  {
    spin_unlock(&baldo_ready_lock);
    return 0;
  }
  spin_unlock(&baldo_ready_lock);

  long unsigned int baldo_daemon_portid = (long unsigned int) info->snd_portid;

  /* 1)  Allocate a new skb */
  struct sk_buff *skb;
  skb = genlmsg_new(sizeof(struct call_data_buffer_s) + GENL_HDRLEN + NLA_HDRLEN, GFP_KERNEL);
  if (!skb)
  {
    printk(KERN_ERR "Baldo: Error creating skb\n");
    goto error;
  }

  /* 2) Create a new header and payload */
  int ret;
  void *msg_head;
  msg_head = genlmsg_put(skb, baldo_daemon_portid, 0, &baldo_genl_family, 0, BALDO_HELLO_CMD);
  if (!msg_head)
  {
    printk(KERN_ERR "Baldo: Error creating message header\n");
    goto error;
  }
  
  /* Add the message */
  unsigned long flags;
  spin_lock_irqsave(&baldo_data_lock, flags);
  if (call_data_buffer->num == 0)
  {
    spin_unlock_irqrestore(&baldo_data_lock, flags);
    nlmsg_free(skb);
    return 0;
  }
  /* Copy the call_data_buffer to the message */
  ret = nla_put(skb, BALDO_DATA, sizeof(struct call_data_buffer_s), call_data_buffer);
  if (ret)
  {
    spin_unlock_irqrestore(&baldo_data_lock, flags);
    printk(KERN_ERR "Baldo: Error creating message\n");
    goto error;
  }
  /* Reset the call_pathname */
  call_data_buffer->num = 0;
  spin_unlock_irqrestore(&baldo_data_lock, flags);
  
  /* End the message */
  genlmsg_end(skb, msg_head);

  /* 3) Send the message */
  //ret = genlmsg_multicast(&baldo_genl_family, skb, baldo_daemon_portid, NETLINK_BALDO_GROUP, GFP_KERNEL);
  //ret = genlmsg_unicast(&init_net, skb, baldo_daemon_portid);
  ret = genlmsg_reply(skb, info);
  if (ret < 0)
  {
    printk(KERN_ERR "Baldo: Error sending message\n");
    goto error;
  }

  return 0;
error:
  return -1;
}

int baldo_genl_block_ip(struct sk_buff *message, struct genl_info *info)
{
  if (info->attrs[BALDO_IPv4])
  {
    __be32 ip = nla_get_u32(info->attrs[BALDO_IPv4]);
    struct ip_entry *entry;
    entry = kmalloc(sizeof(struct ip_entry), GFP_KERNEL);
    if (!entry)
    {
      printk(KERN_ERR "Baldo: Error allocating memory\n");
      return -1;
    }
    entry->ip = ip;
    hash_add_rcu(baldo_blocked, &entry->node, ip);
    printk(KERN_INFO "Baldo: Added IP %p to the blocked list\n", &ip);
    return 0;
  }

  printk(KERN_ERR "Baldo: No IP address provided\n");
  return -1;
}

int baldo_genl_unblock_ip(struct sk_buff *message, struct genl_info *info)
{
  if (info->attrs[BALDO_IPv4])
  {
    __be32 ip = nla_get_u32(info->attrs[BALDO_IPv4]);
    struct ip_entry *entry;
    
    hash_for_each_possible_rcu(baldo_blocked, entry, node, ip)
    {
      if (entry->ip == ip)
      {
        hash_del_rcu(&entry->node);
        kfree(entry);
        printk(KERN_INFO "Baldo: Removed IP %p from the blocked list\n", &ip);
        return 0;
      }
    }
    
    return 0;
  }

  printk(KERN_ERR "Baldo: No IP address provided\n");
  return -1;
}

MODULE_LICENSE("GPL");

#endif // BALDO_NETLINK
