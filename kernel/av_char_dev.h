#ifndef _AV_CHAR_DEV_H
#define _AV_CHAR_DEV_H

#ifdef AV_CHAR_DEV

#include <linux/fs.h>     /* contains file_operations structure */
#include <linux/cdev.h>

#include "av_common.h"

#define MAX_INTEGER_CHAR 10
#define AV_NOTIFY_MINOR 1
#define AV_FIREWALL_MINOR 2

/* The size of the serialized data is the sum of the sizes of the
 * serialized data and the serialized call_data struct, plus some
 * extra space for the separators and the null terminator */
#define AV_SERIALIZED_DATA_SIZE MAX_STRING_SIZE + MAX_SYMBOL_SIZE + 10*4 + 7
#define AV_SERIALIZED_BUFFER_SIZE AV_SERIALIZED_DATA_SIZE * MAX_DATA_BUFFER_SIZE + 10 + 2

extern dev_t av_dev;
extern struct class *av_cdev_class;

extern struct cdev av_firewall_cdev;
extern struct cdev av_notify_cdev;

extern const struct file_operations av_firewall_ops;
extern const struct file_operations av_notify_ops;

ssize_t av_firewall_write(struct file *file, const char __user *buf, size_t count, loff_t *offset);

/* Data structure to hold the data to send during notify_read */
struct notify_data {
    struct cdev av_cdev;
    char buffer[AV_SERIALIZED_BUFFER_SIZE];
};

/* Copies the data from the global data buffer to notify_data->buffer */
int av_notify_open(struct inode *inode, struct file *file);

ssize_t av_notify_read(struct file *file, char __user *buf, size_t count, loff_t *offset);

/**
 * @brief Write to the notify device
 *
 * Accepts the following commands:
 * - HELLO: Set the ready flag to true
 *   - Returns 1
 *   - Example: echo "HELLO" > /dev/av_notify
 * - BYE: Set the ready flag to false
 *   - Returns 1
 *   - Example: echo "BYE" > /dev/av_notify
 * - Anything else: Returns 0
 */
ssize_t av_notify_write(struct file *file, const char __user *buf, size_t count, loff_t *offset);

char *av_serialize_call_data_buffer(void);
char *av_serialize_call_data(struct call_data data);

#endif // AV_CHAR_DEV

#endif
