#ifndef _AV_COMMON_H
#define _AV_COMMON_H

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/spinlock.h>     /* spinlocks */

#define MAX_STRING_SIZE 1024
#define MAX_SYMBOL_SIZE 80      /* found experimentally */
#define MAX_DATA_BUFFER_SIZE 10 /* the limit of a netlink message
                                   appears to be 16KB */

extern spinlock_t av_ready_lock;
extern bool send_ready;

/* Spinlock protecting the variable to send
 * Note that "spin_lock_irqsave" is used to disable
 * interrupts while holding the lock, "spin_lock" does not. */
extern spinlock_t av_data_lock;

/* See linux/shed.h for the definition of struct task_struct,
 * where we can take data from */
struct call_data
{
    int pid;                        /* process id */
    int ppid;                       /* parent process id, current->real_parent->pid */
    int tgid;                       /* thread group id */
    unsigned int uid;               /* user id */
    char symbol[MAX_SYMBOL_SIZE]; 
    char data[MAX_STRING_SIZE];
} __attribute__( ( packed ) );      /* This is to ensure that the struct
                                     * is packed and no padding is added */

struct call_data_buffer_s
{
    int index;
    struct call_data data[MAX_DATA_BUFFER_SIZE];
} __attribute__( ( packed ) );

extern struct call_data_buffer_s *call_data_buffer;

#endif
