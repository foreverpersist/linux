// SPDX-License-Identifier: GPL-2.0
#ifndef _LINUX_SCI_H
#define _LINUX_SCI_H

#ifdef CONFIG_SYSCALL_ISOLATION
#include <asm/sci.h>
#else
static inline int sci_init(struct task_struct *tsk) { return 0; }
static inline void sci_exit(struct task_struct *tsk) {}
#endif

#endif /* _LINUX_SCI_H */
