#ifndef _AV_COMMON_H
#define _AV_COMMON_H

#define MAX_STRING_SIZE 1024

static DEFINE_SPINLOCK(av_ready_lock);
static bool send_ready = false;

/* Spinlock protecting the variable to send
 * Note that "spin_lock_irqsave" is used to disable
 * interrupts while holding the lock, "spin_lock" does not. */
static DEFINE_SPINLOCK(av_data_lock);
static char call_pathname[MAX_STRING_SIZE] = {"\0"};

#endif
