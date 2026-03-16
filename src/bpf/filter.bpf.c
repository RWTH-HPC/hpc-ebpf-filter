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
static __noinline void log_event(u32 uid, enum Operation operation,
                                 union OperationDetails details) {
    struct Event *event = bpf_ringbuf_reserve(&EVENTS, sizeof(struct Event), 0);
    if (event != NULL) {
        event->pid = bpf_get_current_pid_tgid() >> 32;
        event->uid = uid;
        event->operation = operation;
        event->operation_details = details;
        bpf_get_current_comm(&event->comm, sizeof(event->comm));
        bpf_ringbuf_submit(event, 0);
    }
}

static __always_inline bool get_netlink_message_type(struct sk_buff *skb,
                                                     u16 *retval) {
    const void *const head = skb->head;
    const u32 len = skb->len;
    // nlmsghdr is a UAPI type, so we can assume the layout never changes
    // and don't need to use CO_RE to retrieve members
    struct nlmsghdr nlh;

    if (head == NULL || len < sizeof(nlh)) {
        return false;
    }
    if (bpf_probe_read_kernel(&nlh, sizeof(nlh), head) != 0) {
        return false;
    }
    if (nlh.nlmsg_len < sizeof(nlh) || nlh.nlmsg_len > len) {
        return false;
    }

    *retval = nlh.nlmsg_type;
    return true;
}

static __always_inline bool is_readonly_rtnl_type(u16 message_type) {
    switch (message_type) {
    case RTM_GETLINK:
    case RTM_GETADDR:
    case RTM_GETROUTE:
    case RTM_GETNEIGH:
    case RTM_GETRULE:
    case RTM_GETQDISC:
    case RTM_GETTCLASS:
    case RTM_GETTFILTER:
    case RTM_GETACTION:
    case RTM_GETMULTICAST:
    case RTM_GETANYCAST:
    case RTM_GETNEIGHTBL:
    case RTM_GETADDRLABEL:
    case RTM_GETDCB:
    case RTM_GETNETCONF:
    case RTM_GETMDB:
    case RTM_GETNSID:
    case RTM_GETSTATS:
    case RTM_GETCHAIN:
    case RTM_GETNEXTHOP:
    case RTM_GETLINKPROP:
    case RTM_GETVLAN:
    case RTM_GETNEXTHOPBUCKET:
    case RTM_GETTUNNEL:
    case RTM_NEWPREFIX:
    case RTM_NEWNDUSEROPT:
    case RTM_NEWSTATS:
    case RTM_NEWCACHEREPORT:
        return true;
    default:
        return false;
    }
}

SEC("lsm/socket_setsockopt")
int BPF_PROG(deny_setsockopt, struct socket *sock, int level, int optname) {
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
        case IPT_SO_SET_ADD_COUNTERS:
            log_event(uid, SETSOCKOPT,
                      (union OperationDetails){
                          .setsockopt.optname = optname,
                      });
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

    u16 netlink_message_type = 0;

    bool denied = false;
    switch (sk->sk_protocol) {
    case NETLINK_ROUTE:
        if (!get_netlink_message_type(skb, &netlink_message_type)) {
            denied = true;
            break;
        }
        if (!is_readonly_rtnl_type(netlink_message_type)) {
            denied = true;
        }
        break;
    case NETLINK_NFLOG:
    case NETLINK_XFRM:
    case NETLINK_NETFILTER:
        denied = true;
    }

    if (denied) {
        log_event(uid, NETLINK_SEND,
                  (union OperationDetails){
                      .netlink_send.family = sk->sk_protocol,
                      .netlink_send.message_type = netlink_message_type});
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

    bool denied = false;
    switch (family) {
    case (AF_INET):
        if (type == SOCK_PACKET) {
            denied = true;
        }
        break;
    case (AF_NETLINK):
        switch (protocol) {
        case NETLINK_NFLOG:
        case NETLINK_XFRM:
        case NETLINK_NETFILTER:
            denied = true;
        }
        break;
    case (AF_KEY):
    case (AF_PACKET):
        denied = true;
    }

    if (denied) {
        log_event(uid, SOCKET_CREATE,
                  (union OperationDetails){
                      .socket_create = {.family = family,
                                        .type = type,
                                        .protocol = {protocol}}});
        return -EACCES;
    }

    return 0;
}
