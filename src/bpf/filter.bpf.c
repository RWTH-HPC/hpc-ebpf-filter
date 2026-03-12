#if defined(CLANG_TIDY)
// required for PT_REGS macros to not error
#define __BPF_TARGET_MISSING ""
#endif

// #include "clone_defines.h"
#include "iptables_defines.h"
#include "netlink_defines.h"
#include "shared.h"
#include "socket_defines.h"
#include "vmlinux.h"

#include <asm/unistd.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/errno.h>

const char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(key_size, 0);
    __uint(value_size, 0);
    __uint(max_entries, 4096);
} EVENTS SEC(".maps");

/*
struct {
    __uint(type, BPF_MAP_TYPE_INODE_STORAGE);
    __type(key, u32);
    __type(value, u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 0);
} ALLOWED_FILES SEC(".maps");
*/

static __always_inline bool is_allowed_user(u32 uid) { return uid < 1000; }

/*
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
*/

// this always ends with a denial, so don't bother inlining it
static __noinline void log_event(enum Operation operation) {
    const u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    struct Event *event = bpf_ringbuf_reserve(&EVENTS, sizeof(struct Event), 0);
    if (event != NULL) {
        event->pid = bpf_get_current_pid_tgid() >> 32;
        event->uid = uid;
        event->operation = operation;
        bpf_get_current_comm(&event->comm, sizeof(event->comm));
        bpf_ringbuf_submit(event, 0);
    }
}

static __always_inline bool is_tc_operation(struct sk_buff *skb) {
    void *head = BPF_CORE_READ(skb, head);
    u32 len = BPF_CORE_READ(skb, len);
    struct nlmsghdr nlh;

    // sanity checks - the kernel does not verify that the message is
    // well-formed until later
    if (head == NULL || len < sizeof(nlh)) {
        return true;
    }
    if (bpf_probe_read_kernel(&nlh, sizeof(nlh), head) != 0) {
        return true;
    }
    if (nlh.nlmsg_len < sizeof(nlh) || nlh.nlmsg_len > len) {
        return true;
    }

    switch (nlh.nlmsg_type) {
    case RTM_NEWQDISC:
    case RTM_DELQDISC:
    case RTM_NEWTCLASS:
    case RTM_DELTCLASS:
    case RTM_NEWTFILTER:
    case RTM_DELTFILTER:
    case RTM_NEWACTION:
    case RTM_DELACTION:
        return true;
    }

    return false;
}

SEC("lsm/socket_setsockopt")
int BPF_PROG(deny_iptables, struct socket *sock, int level, int optname) {
    const u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    if (is_allowed_user(uid)) {
        return 0;
    }

    if (level == IPPROTO_IP || level == IPPROTO_IPV6) {
        // values for IPv4 and IPv6 are the same
        switch (optname) {
        case IPT_SO_SET_REPLACE:
            log_event(OP_SETSOCKOPT_IPT_SO_SET_REPLACE);
            return -EPERM;
        case IPT_SO_SET_ADD_COUNTERS:
            log_event(OP_SETSOCKOPT_IPT_SO_SET_ADD_COUNTERS);
            return -EPERM;
        }
    }

    return 0;
}

SEC("lsm/netlink_send")
int BPF_PROG(deny_netlink_send, struct sock *sk, struct sk_buff *skb) {
    const u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    if (is_allowed_user(uid)) {
        return 0;
    }

    switch (BPF_CORE_READ(sk, sk_protocol)) {
    case NETLINK_ROUTE:
        if (is_tc_operation(skb)) {
            log_event(OP_NETLINK_SEND_ROUTE_TC);
            return -EPERM;
        }
        break;
    case NETLINK_NFLOG:
        log_event(OP_NETLINK_SEND_NFLOG);
        return -EPERM;
    case NETLINK_XFRM:
        log_event(OP_NETLINK_SEND_XFRM);
        return -EPERM;
    case NETLINK_NETFILTER:
        log_event(OP_NETLINK_SEND_NETFILTER);
        return -EPERM;
    }

    return 0;
}

SEC("lsm/socket_create")
int BPF_PROG(deny_socket_create, int family, int type, int protocol, int kern) {
    if (kern != 0) {
        return 0;
    }

    const u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    if (is_allowed_user(uid)) {
        return 0;
    }

    switch (family) {
    case (AF_INET):
        if (type == SOCK_PACKET) {
            log_event(OP_SOCKET_CREATE_AF_INET_SOCK_PACKET);
            return -EPERM;
        }
        break;
    case (AF_KEY):
        log_event(OP_SOCKET_CREATE_AF_KEY);
        return -EPERM;
    case (AF_NETLINK):
        switch (protocol) {
        case NETLINK_NFLOG:
            log_event(OP_SOCKET_CREATE_AF_NETLINK_NFLOG);
            return -EPERM;
        case NETLINK_XFRM:
            log_event(OP_SOCKET_CREATE_AF_NETLINK_XFRM);
            return -EPERM;
        case NETLINK_NETFILTER:
            log_event(OP_SOCKET_CREATE_AF_NETLINK_NETFILTER);
            return -EPERM;
        }
        break;
    case (AF_PACKET):
        log_event(OP_SOCKET_CREATE_AF_PACKET);
        return -EPERM;
    }

    return 0;
}

/*
SEC("lsm/capable")
int BPF_PROG(deny_netns_capable, const struct cred *cred,
             struct user_namespace *ns, int cap, unsigned int opts, int ret) {
    if (ret != 0) {
        return ret;
    }

    // check for uid first to reduce impact on system processes
    const u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    if (is_allowed_user(uid)) {
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

    log_event(OP_CREATE_NETNS);

    return -EPERM;
}
*/
