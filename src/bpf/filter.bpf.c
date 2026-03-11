#if defined(CLANG_TIDY)
// required for PT_REGS macros to not error
#define __BPF_TARGET_MISSING ""
#endif

#include "clone_defines.h"
#include "shared.h"
#include "vmlinux.h"

#include <asm/unistd.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

const char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(key_size, 0);
    __uint(value_size, 0);
    __uint(max_entries, 4096);
} EVENTS SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_INODE_STORAGE);
    __type(key, u32);
    __type(value, u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 0);
} ALLOWED_FILES SEC(".maps");

static __always_inline bool is_allowed_file(const struct file *file) {
    struct inode *inode = __builtin_preserve_access_index(file->f_inode);
    if (!inode) {
        return false;
    }

    const u8 *allowed = bpf_inode_storage_get(&ALLOWED_FILES, inode, NULL, 0);
    return allowed != NULL;
}

static __always_inline bool is_allowed_binary(struct task_struct *task) {
    struct file *exe = bpf_get_task_exe_file(task);
    if (!exe) {
        return false;
    }

    const bool allowed = is_allowed_file(exe);
    bpf_put_file(exe);
    return allowed;
}

SEC("lsm/capable")
int BPF_PROG(deny_netns_capable, const struct cred *cred,
             struct user_namespace *ns, int cap, unsigned int opts, int ret) {
    if (ret != 0) {
        return ret;
    }

    // check for uid first to reduce impact on system processes
    const u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    if (uid < 1000) {
        return 0;
    }

    struct task_struct *task = bpf_get_current_task_btf();
    struct pt_regs *regs = (struct pt_regs *)bpf_task_pt_regs(task);
    const int syscall = BPF_CORE_READ(regs, orig_ax);

    if (syscall != __NR_unshare && syscall != __NR_clone &&
        syscall != __NR_clone3) {
        return 0;
    }

    const unsigned long flags = PT_REGS_PARM1_CORE_SYSCALL(regs);
    if (!(flags & CLONE_NEWNET)) {
        return 0;
    }

    if (is_allowed_binary(task)) {
        return 0;
    }

    struct Event *event = bpf_ringbuf_reserve(&EVENTS, sizeof(struct Event), 0);
    if (event != NULL) {
        event->pid = bpf_get_current_pid_tgid() >> 32;
        event->uid = uid;
        switch (syscall) {
        case __NR_unshare:
            event->syscall = UNSHARE;
            break;
        case __NR_clone:
            event->syscall = CLONE;
            break;
        case __NR_clone3:
            event->syscall = CLONE3;
            break;
        default:
            event->syscall = SC_UNKNOWN;
            break;
        }
        bpf_get_current_comm(&event->comm, sizeof(event->comm));
        bpf_ringbuf_submit(event, 0);
    }

    return -1;
}
