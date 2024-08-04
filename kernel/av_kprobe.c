/* Kernel headers */
#include <linux/kernel.h>
#include <linux/module.h>

/* Kprobe headers */
#include <linux/kprobes.h>

/* Netlink headers */
#include <linux/netlink.h>     /* netlink_kernel_create, netlink_kernel_release */
#include <net/genetlink.h>     /* genl_register_family */
#include <net/netlink.h>       /* nla_put_string */

#define MODULE_NAME "av_kprobe"
#define NETLINK_AV_GROUP 31

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Giovanni");
MODULE_DESCRIPTION("Kprobe hook for the antivirus daemon");

static unsigned int av_daemon_portid = 0;

/**
 * Here we are creating a family for the netlink communication,
 * we will be able to send predefined commands to the kernel module
 * from the user space.
 */

/* attribute types: values passed with a command */
enum {
    AV_UNSPEC,
    AV_MSG,   /* String message */
    __AV_MAX,
};
#define AV_MAX (__AV_MAX - 1)

/* A policy for the family */
static struct nla_policy av_genl_policy[AV_MAX + 1] = {
    [AV_MSG] = { .type = NLA_NUL_STRING }, /* Null terminated strings */
};

/* Operation handler */
static int av_genl_hello(struct sk_buff *skb, struct genl_info *info) {
    printk(KERN_INFO "AV: Client HELLO\n");
    av_daemon_portid = (long unsigned int) info->snd_portid;
    return 0;
}

static int av_genl_bye(struct sk_buff *skb, struct genl_info *info) {
    printk(KERN_INFO "AV: Client BYE\n");
    av_daemon_portid = 0;
    return 0;
}

/* Operation Commands */
enum {
    AV_UNSPEC_CMD,
    AV_HELLO_CMD,   /* hello command,  requests connection */
    AV_BYE_CMD,     /* bye command,    close connection */
    AV_NOTIFY_CMD,  /* notify command, just send a payload */
    __AV_MAX_CMD,
};
#define AV_MAX_CMD (__AV_MAX_CMD - 1)

/* Operation definition */
static struct genl_ops av_genl_ops[] = {
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
};

/* Family definition: a family is a group of commands and
 * associated operations. */
static struct genl_family av_genl_family = {
    .id = 0,           /* Automatica ID generation */
    .hdrsize = 0,
    .name = "AV_GENL",
    .version = 1,
    .maxattr = AV_MAX,
    .ops = av_genl_ops,
    .n_ops = ARRAY_SIZE(av_genl_ops),
};

/* This function gets called when the kprobe is hit
 *
 * `pt_regs` is defined based on your architecture
 * x86 is defined in "arch/x86/include/asm/ptrace.h" */
int av_pre_handler(struct kretprobe_instance *p, struct pt_regs *regs) {

    printk(KERN_INFO "AV: openat called");

    // TODO: Send the filename and the process that called it

    /* Get the args */
    int fd = (int) regs->di;
    const char *filename = (const char *)regs->si;
    // TODO: Copy from user space to kernel space
    int flags = (int) regs->dx;
    umode_t mode = (umode_t) regs->r10;

    /* Send a message using netlink */

    if (av_daemon_portid == 0) {
        printk(KERN_ERR "AV: Daemon PID not set\n");
        goto exit;
    }

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
    msg_head = genlmsg_put(skb, 0, 0, &av_genl_family, 0, AV_UNSPEC_CMD);
    if (!msg_head) {
        printk(KERN_ERR "AV: Error creating message header\n");
        goto error;
    }
    /* Add the message */
    ret = nla_put_string(skb, AV_MSG, "Hello from kernel\n");
    if (ret) {
        printk(KERN_ERR "AV: Error creating message\n");
        goto error;
    }
    /* End the message */
    genlmsg_end(skb, msg_head);

    /* 3) Set the message */
    //ret = genlmsg_multicast(&av_genl_family, skb, 0, NETLINK_AV_GROUP, GFP_KERNEL);
    ret = genlmsg_unicast(&init_net, skb, av_daemon_portid);
    if (ret) {
        printk(KERN_ERR "AV: Error sending message\n");
        goto error;
    }

exit:
    return 0;

error:
    return -1;
}

/* Symbol names are found in System.map */
static struct kretprobe kp_ret = {
    .entry_handler = av_pre_handler,
    .kp = {
        .symbol_name = "__x64_sys_openat",
    },
};

static int __init av_init(void)
{
/* Only support for x86_64 */
#ifdef __x86_64__ 
    printk(KERN_INFO "AV: Module loaded\n");

    int ret;
    if ((ret = register_kretprobe(&kp_ret)) < 0) {
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
    unregister_kretprobe(&kp_ret);

    genl_unregister_family(&av_genl_family);

    printk(KERN_INFO "AV: Module unloaded\n");
#endif
}

module_init(av_init);
module_exit(av_exit);
