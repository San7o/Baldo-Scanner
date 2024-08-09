#include "av_common.h"

DEFINE_SPINLOCK(av_ready_lock);
bool send_ready = false;

/* Spinlock protecting the variable to send
 * Note that "spin_lock_irqsave" is used to disable
 * interrupts while holding the lock, "spin_lock" does not. */
DEFINE_SPINLOCK(av_data_lock);
char call_pathname[MAX_STRING_SIZE] = {"\0"};