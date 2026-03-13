#if defined(CLANG_TIDY)
// required for PT_REGS macros to not error
#define __BPF_TARGET_MISSING ""
#endif

#include "iptables_defines.h"
#include "netlink_defines.h"
#include "shared.h"
#include "socket_defines.h"
#include "vmlinux.h"

#include <asm/unistd.h>
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

static __always_inline bool is_allowed_user(u32 uid) { return uid < 1000; }

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
    const void *const head = skb->head;
    const u32 len = skb->len;
    // nlmsghdr is a UAPI type, so we can assume the layout never changes
    // and don't need to use CO_RE to retrieve members
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

    // POSIX does not define a "not allowed" failure mode for setsockopt,
    // so use EPERM

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

    switch (sk->sk_protocol) {
    case NETLINK_ROUTE:
        if (is_tc_operation(skb)) {
            log_event(OP_NETLINK_SEND_ROUTE_TC);
            return -EACCES;
        }
        break;
    case NETLINK_NFLOG:
        log_event(OP_NETLINK_SEND_NFLOG);
        return -EACCES;
    case NETLINK_XFRM:
        log_event(OP_NETLINK_SEND_XFRM);
        return -EACCES;
    case NETLINK_NETFILTER:
        log_event(OP_NETLINK_SEND_NETFILTER);
        return -EACCES;
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
            return -EACCES;
        }
        break;
    case (AF_KEY):
        log_event(OP_SOCKET_CREATE_AF_KEY);
        return -EACCES;
    case (AF_NETLINK):
        switch (protocol) {
        case NETLINK_NFLOG:
            log_event(OP_SOCKET_CREATE_AF_NETLINK_NFLOG);
            return -EACCES;
        case NETLINK_XFRM:
            log_event(OP_SOCKET_CREATE_AF_NETLINK_XFRM);
            return -EACCES;
        case NETLINK_NETFILTER:
            log_event(OP_SOCKET_CREATE_AF_NETLINK_NETFILTER);
            return -EACCES;
        }
        break;
    case (AF_PACKET):
        log_event(OP_SOCKET_CREATE_AF_PACKET);
        return -EACCES;
    }

    return 0;
}
