#include <linux/module.h>
#define MODULE_NAME "hello"
static int __init hello_init(void)
{
    printk(KERN_INFO "hello world!\n");
    return 0;
}
static void __exit hello_cleanup(void) {
    printk(KERN_INFO "bye world!\n");
}
module_init(hello_init);
module_exit(hello_cleanup);
MODULE_LICENSE("MIT");
