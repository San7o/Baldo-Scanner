#ifndef _AV_COMMON_H
#define _AV_COMMON_H

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/spinlock.h>    /* spinlocks */

#define MAX_STRING_SIZE 1024

extern spinlock_t av_ready_lock;
extern bool send_ready;

/* Spinlock protecting the variable to send
 * Note that "spin_lock_irqsave" is used to disable
 * interrupts while holding the lock, "spin_lock" does not. */
extern spinlock_t av_data_lock;
extern char call_pathname[MAX_STRING_SIZE];

#endif
