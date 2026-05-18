#ifdef CLANG_TIDY
// required for PT_REGS macros to not error
#define __BPF_TARGET_MISSING "" // NOLINT(bugprone-reserved-identifier)
#endif

#include "external/kernel/iptables_defines.h"
#ifndef ROCKY_8
#include "netlink.bpf.h"
#endif
#include "common.bpf.h"
#include "external/kernel/netlink_defines.h"
#include "external/kernel/socket_defines.h"
#include "shared.h"
#include "vmlinux.h"

// NOLINTNEXTLINE(bugprone-suspicious-include)
#include "ptrace_dumpable.bpf.c" // IWYU pragma: keep

#include <asm-generic/errno-base.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

const char LICENSE[] SEC("license") = "GPL";

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

    const u8 target[10] = "authencesn";
    for (int i = 0; i < sizeof(target); i++) {
        if (alg.salg_name[i] != target[i]) {
            return false;
        }
    }

    return true;
}

SEC("lsm/socket_setsockopt")
int BPF_PROG(deny_setsockopt, struct socket *sock, int level, int optname,
             int ret) {
    if (ret != 0) {
        return ret;
    }

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
        default:
            break;
        }
    }

    return 0;
}

SEC("lsm/netlink_send")
int BPF_PROG(deny_netlink_send, struct sock *sk, struct sk_buff *skb, int ret) {
    if (ret != 0) {
        return ret;
    }

    const u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    if (is_allowed_user(uid)) {
        return 0;
    }

    u16 netlink_message_type = 0;

    bool denied = false;
    const u16 protocol = BPF_CORE_READ_BITFIELD(sk, sk_protocol);
    switch (protocol) {
    case NETLINK_ROUTE:
#ifndef ROCKY_8
        if (skb_has_forbidden_rtnl_msg(skb, &netlink_message_type)) {
            denied = true;
        }
#endif
        break;
    case NETLINK_NFLOG:
    case NETLINK_XFRM:
    case NETLINK_NETFILTER:
        denied = true;
        break;
    default:
        break;
    }

    if (denied) {
        log_event(uid, NETLINK_SEND,
                  (union OperationDetails){.netlink_send.family = protocol,
                                           .netlink_send.message_type =
                                               netlink_message_type});
        return -EACCES;
    }

    return 0;
}

SEC("lsm/socket_create")
int BPF_PROG(deny_socket_create, int family, int type, int protocol, int kern,
             int ret) {
    if (ret != 0) {
        return ret;
    }

    if (kern != 0) {
        return 0;
    }

    const u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    if (is_allowed_user(uid)) {
        return 0;
    }

    bool denied = false;
    switch (family) {
    case AF_INET:
    case AF_INET6:
        if (type == SOCK_PACKET) {
            denied = true;
        }
        break;
    case AF_NETLINK:
        switch (protocol) {
        case NETLINK_NFLOG:
        case NETLINK_XFRM:
        case NETLINK_NETFILTER:
            denied = true;
            break;
        default:
            break;
        }
        break;
    case AF_UNSPEC:
    case AF_UNIX:
    case AF_IB:
    case AF_XDP:
        break;
    default:
        denied = true;
        break;
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
             int addrlen, int ret) {
    if (ret != 0) {
        return ret;
    }

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
