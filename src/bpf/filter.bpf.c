#include <asm-generic/errno-base.h>
#if defined(CLANG_TIDY)
// required for PT_REGS macros to not error
#define __BPF_TARGET_MISSING ""
#endif

#include "iptables_defines.h"
#include "netlink.bpf.h"
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

// this is essentially sockaddr_alg_new but without the VLA
struct sockaddr_alg_min {
    u16 salg_family;
    u8 salg_type[14];
    u32 salg_feat;
    u32 salg_mask;
    u8 salg_name[10];
};

static __always_inline bool is_authencesn_socket(struct sockaddr *address,
                                                 int addrlen) {
    if (addrlen < sizeof(struct sockaddr_alg_min)) {
        return false;
    }

    struct sockaddr_alg_min alg;
    if (bpf_probe_read_kernel(&alg, sizeof(alg), address) != 0) {
        return false;
    }

    if (alg.salg_family != AF_ALG) {
        return false;
    }

    const char target[10] = "authencesn";
    for (int i = 0; i < 10; i++) {
        if (alg.salg_name[i] != target[i]) {
            return false;
        }
    }

    return true;
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
        if (skb_has_forbidden_rtnl_msg(skb, &netlink_message_type)) {
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

SEC("lsm/socket_bind")
int BPF_PROG(deny_socket_bind, struct socket *sock, struct sockaddr *address,
             int addrlen) {
    const u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    if (is_allowed_user(uid)) {
        return 0;
    }

    // CVE-2026-31431
    if (is_authencesn_socket(address, addrlen)) {
        log_event(uid, SOCKET_BIND,
                  (union OperationDetails){.socket_bind = {.family = AF_ALG}});
        return -EACCES;
    }

    return 0;
}
