#ifdef AV_CHAR_DEV

#include <linux/uaccess.h>
#include <linux/hashtable.h>

#include "av_char_dev.h"
#include "av_firewall.h"
#include "av_common.h"

dev_t av_dev = 0;
struct class *av_cdev_class = NULL;

struct cdev av_notify_cdev;
struct cdev av_firewall_cdev;

const struct file_operations av_firewall_ops =
{
    .owner = THIS_MODULE,
    .write = av_firewall_write,
};

const struct file_operations av_notify_ops =
{
    .owner = THIS_MODULE,
    .read = av_notify_read,
    .write = av_notify_write,
    .open = av_notify_open,
};

ssize_t av_firewall_write(struct file *file, const char __user *buf,
                size_t count, loff_t *offset)
{
    uint32_t ip = 0;
    if (kstrtou32_from_user(buf, count, 10, &ip) != 0)
    {
        printk(KERN_ERR "AV: Error converting string to int\n");
        return -EINVAL;
    }
    struct ip_entry *entry;
    entry = kmalloc(sizeof(struct ip_entry), GFP_KERNEL);
    if (!entry)
    {
        printk(KERN_ERR "AV: Error allocating memory\n");
        return -ENOMEM;
    }
    entry->ip = ip;
    hash_add_rcu(av_blocked, &entry->node, ip);
    printk(KERN_INFO "AV: Added IP %p to the blocked list\n", &ip);
    return count;
}

int av_notify_open(struct inode *inode, struct file *file) {

    /* Check if the device is already open */
    if (file->private_data != NULL)
    {
        return -EBUSY;
    }

    struct notify_data *my_data = container_of(inode->i_cdev, struct notify_data, av_cdev);
    file->private_data = my_data;

    /* Initialize buffer */
    unsigned long flags;
    spin_lock_irqsave(&av_data_lock, flags);
    
    for (int i = 0; i < AV_SERIALIZED_BUFFER_SIZE; i++)
    {
        my_data->buffer[i] = 0;
    }

    char* serialized_data = av_serialize_call_data_buffer();
    int res = raw_copy_to_user(my_data->buffer,
                    serialized_data,
                    strlen(serialized_data));
    if (res)
    {
        spin_unlock_irqrestore(&av_data_lock, flags);
        kfree(serialized_data);
        return -1;
    }
    spin_unlock_irqrestore(&av_data_lock, flags);
    kfree(serialized_data);

    return 0;
}

ssize_t av_notify_read(struct file *file, char __user *buf, size_t count,
                loff_t *offset)
{
    struct notify_data *data = (struct notify_data*) file->private_data;

    ssize_t len = min((ssize_t) (strlen(data->buffer) - *offset), (ssize_t) count);
    if (len <= 0)
    {
        return 0;
    }

    if (raw_copy_to_user(buf, data->buffer + *offset, len))
    {
        printk(KERN_ERR "AV: Error copying data to user\n");

        return -EFAULT;
    }

    *offset += len;
    return len;
}

ssize_t av_notify_write(struct file *file, const char __user *buf,
                size_t count, loff_t *offset)
{
    unsigned long flags;
    if (strncmp(buf, "HELLO", 5) == 0)
    {
        spin_lock_irqsave(&av_ready_lock, flags);
        send_ready = true;
        spin_unlock_irqrestore(&av_ready_lock, flags);
        printk(KERN_INFO "AV: Client HELLO\n");
        return count;
    }
    else if (strncmp(buf, "BYE", 3) == 0)
    {
        spin_lock_irqsave(&av_data_lock, flags);
        send_ready = false;
        spin_unlock_irqrestore(&av_data_lock, flags);
        printk(KERN_INFO "AV: Client BYE\n");
        return count;
    }

    /* Updates the data buffer and resets the buffer index */
    else if (strncmp(buf, "FETCH", 5) == 0)
    {
        struct notify_data *my_data = (struct notify_data*) file->private_data;

        /* Initialize buffer */
        unsigned long flags;
        spin_lock_irqsave(&av_data_lock, flags);
        char* serialized_data = av_serialize_call_data_buffer();
        int len = strlen(serialized_data);
        int res = raw_copy_to_user(my_data->buffer, serialized_data, len);
        if (res)
        {
            spin_unlock_irqrestore(&av_data_lock, flags);
            kfree(serialized_data);
            return -1;
        }
        call_data_buffer->index = 0;
        spin_unlock_irqrestore(&av_data_lock, flags);
        kfree(serialized_data);

        printk(KERN_INFO "AV: Client FETCH\n");
        return count;
    }

    return -EINVAL;
}

/* Note: the buffer needs to be freed after usage */
char *av_serialize_call_data_buffer()
{
    char *buffer = kmalloc(AV_SERIALIZED_BUFFER_SIZE, GFP_KERNEL);
    sprintf(buffer, "%d\n", call_data_buffer->index);
    for (int i = 0; i < call_data_buffer->index; i++)
    {
        char* serialized = av_serialize_call_data(call_data_buffer->data[i]);
        strncat(buffer, serialized, AV_SERIALIZED_DATA_SIZE);
        kfree(serialized);
    }
    return buffer;
}

/* Note: the buffer needs to be freed after usage */
char *av_serialize_call_data(struct call_data data)
{
    char *buffer = kmalloc(AV_SERIALIZED_DATA_SIZE,
                    GFP_KERNEL);
    sprintf(buffer, "%d,%d,%d,%u,%s,%s\n",
                    data.pid, data.ppid, data.tgid, data.uid,
                    data.symbol, data.data);
    return buffer;
}

#endif
