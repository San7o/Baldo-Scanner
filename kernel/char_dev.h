// SPDX-License-Identifier: GPL-2.0+
// Author:  Giovanni Santini
// Mail:    giovanni.santini@proton.me
// Github:  @San7o

#ifndef _BALDO_CHAR_DEV_H
#define _BALDO_CHAR_DEV_H

#ifdef BALDO_CHAR_DEV

#include <linux/fs.h>     /* contains file_operations structure */
#include <linux/cdev.h>

#include "common.h"

#define MAX_INTEGER_CHAR 10
#define BALDO_NOTIFY_MINOR 1
#define BALDO_FIREWALL_MINOR 2

/* The size of the serialized data is the sum of the sizes of the
 * serialized data and the serialized call_data struct, plus some
 * extra space for the separators and the null terminator */
#define BALDO_SERIALIZED_DATA_SIZE MAX_STRING_SIZE + MAX_SYMBOL_SIZE + 10*4 + 7
#define BALDO_SERIALIZED_BUFFER_SIZE BALDO_SERIALIZED_DATA_SIZE * MAX_DATA_BUFFER_SIZE + 10 + 2

extern dev_t baldo_dev;
extern struct class *baldo_cdev_class;

extern struct cdev baldo_firewall_cdev;
extern struct cdev baldo_notify_cdev;

extern const struct file_operations baldo_firewall_ops;
extern const struct file_operations baldo_notify_ops;

ssize_t baldo_firewall_write(struct file *file,
                             const char __user *buf,
                             size_t count,
                             loff_t *offset);

/* Data structure to hold the data to send during notify_read */
struct notify_data {
    struct cdev baldo_cdev;
    char buffer[BALDO_SERIALIZED_BUFFER_SIZE];
};

/* Copies the data from the global data buffer to notify_data->buffer */
int baldo_notify_open(struct inode *inode, struct file *file);

ssize_t baldo_notify_read(struct file *file,
                          char __user *buf,
                          size_t count,
                          loff_t *offset);

/**
 * @brief Write to the notify device
 *
 * Accepts the following commands:
 * - HELLO: Set the ready flag to true
 *   - Returns 1
 *   - Example: echo "HELLO" > /dev/baldo_notify
 * - BYE: Set the ready flag to false
 *   - Returns 1
 *   - Example: echo "BYE" > /dev/baldo_notify
 * - Anything else: Returns 0
 */
ssize_t baldo_notify_write(struct file *file,
                           const char __user *buf,
                           size_t count,
                           loff_t *offset);

char *baldo_serialize_call_data_buffer(void);
char *baldo_serialize_call_data(struct call_data data);

#endif // BALDO_CHAR_DEV

#endif // _BALDO_CHAR_DEV_H
