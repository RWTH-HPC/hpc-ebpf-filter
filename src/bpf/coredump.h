#pragma once

#include <vmlinux.h>
//
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

// taken from coredump.h

// NOLINTBEGIN

#define SUID_DUMP_DISABLE 0 /* No setuid dumping */
#define SUID_DUMP_USER 1    /* Dump as user of process */
#define SUID_DUMP_ROOT 2    /* Dump as root */

/* mm flags */

/* for SUID_DUMP_* above */
#define MMF_DUMPABLE_BITS 2
#define MMF_DUMPABLE_MASK ((1 << MMF_DUMPABLE_BITS) - 1)

/*
 * This returns the actual value of the suid_dumpable flag. For things
 * that are using this for checking for privilege transitions, it must
 * test against SUID_DUMP_USER rather than treating it as a boolean
 * value.
 */
static __always_inline int __get_dumpable(unsigned long mm_flags) {
    return (int)mm_flags & MMF_DUMPABLE_MASK;
}

static __always_inline int get_dumpable(struct mm_struct *mm) {
    unsigned long flags = 0;
    bpf_probe_read_kernel(&flags, sizeof(flags), &mm->flags);
    return __get_dumpable(flags);
}

// NOLINTEND
