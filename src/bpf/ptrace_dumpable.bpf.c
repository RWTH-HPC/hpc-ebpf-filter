#pragma once

#include <vmlinux.h>
//
#include "common.bpf.h"
#include "external/kernel/coredump.h"

#include <asm-generic/errno-base.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifndef ROCKY_8
struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, u32);
    __type(value, bool);
} USER_DUMPABLE SEC(".maps");
#endif

#ifndef ROCKY_8
SEC("fentry/exit_mm_release")
int BPF_PROG(exit_mm_record_ptrace, struct task_struct *task) {
    bool dumpable = get_dumpable(task->mm) == SUID_DUMP_USER;
    bpf_task_storage_get(&USER_DUMPABLE, task, &dumpable,
                         BPF_LOCAL_STORAGE_GET_F_CREATE);

    return 0;
}
#endif

SEC("lsm/ptrace_access_check")
int BPF_PROG(deny_ptrace_access_check, struct task_struct *child,
             unsigned int mode) {
    const u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    if (is_allowed_user(uid)) {
        return 0;
    }

    if (child->mm == NULL) {
#ifdef ROCKY_8
        bool *dumpable = NULL;
#else
        bool *dumpable = bpf_task_storage_get(&USER_DUMPABLE, child, NULL, 0);
#endif
        if (dumpable == NULL || !*dumpable) {
            // this is hit legitimately by utils that list all processes
            // (such as ps) and thus is rather noisy in practice
            // log_event(uid, PTRACE_DUMPABLE_EXPLOIT, (union
            // OperationDetails){});
            return -EPERM;
        }
    }

    return 0;
}
