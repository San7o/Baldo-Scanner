#include "av_kprobe.h"
#include "av_common.h"

struct kprobe kp =
{
    .pre_handler = av_getname_pre_handler,
};

int av_getname_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    //printk(KERN_INFO "AV: getname called");
    //av_dump_registers(regs);
  
    spin_lock(&av_ready_lock);
    if (!send_ready)
    {
        spin_unlock(&av_ready_lock);
        return 0;
    }
    spin_unlock(&av_ready_lock);


    /* Get the filename */
    
    const char __user* user_filename = (const char __user*)
                             regs_get_kernel_argument(regs, 1);
    if (!user_filename)
    {
        printk(KERN_ERR "AV: Error getting filename\n");
        goto error;
    }
    
    char filename[MAX_STRING_SIZE];
    // strncpy_from_user does not work :(
    unsigned long ret = raw_copy_from_user(filename, user_filename,
                    MAX_STRING_SIZE);
    if (ret < 0)
    {
        printk(KERN_ERR "AV: Error copying filename\n");
        goto error;
    }

    spin_lock(&av_data_lock);

    call_data_buffer->num =
            (call_data_buffer->num) % MAX_DATA_BUFFER_SIZE + 1; /* Must be at leas 1 */

    call_data_buffer->data[call_data_buffer->num - 1] = (struct call_data){
        .pid  = current->pid,
        .ppid = current->parent->pid,
        .tgid = current->tgid,
        .uid  = current_uid().val,
    };
    if (strncpy(call_data_buffer->data[call_data_buffer->num - 1].data,
                    filename, MAX_STRING_SIZE) == NULL)
    {
        spin_unlock(&av_data_lock);
        printk(KERN_ERR "AV: Error copying filename\n");
        goto error;
    }
    if (strncpy(call_data_buffer->data[call_data_buffer->num - 1].symbol,
                    "do_sys_open\0", MAX_SYMBOL_SIZE) == NULL)
    {
        spin_unlock(&av_data_lock);
        printk(KERN_ERR "AV: Error copying symbol\n");
        goto error;
    }

    spin_unlock(&av_data_lock);

    return 0;
error:
    return -1;
}

MODULE_LICENSE("GPL");
