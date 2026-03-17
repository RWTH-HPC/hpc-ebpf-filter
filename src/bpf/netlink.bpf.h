#pragma once

#include "netlink_defines.h"
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

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

static __always_inline bool skb_has_forbidden_rtnl_msg(struct sk_buff *skb,
                                                       u16 *message_type) {
    struct nlmsghdr *nlh = (void *)skb->data;
    s64 remaining = skb->len;

    // skb size is soft-capped to 8 KiB
    // in practice, this means 512 iterations at max,
    // but there's no written guarantee
    const u32 num_iters = remaining / sizeof(struct nlmsghdr) + 1;

    if (!nlh || remaining == 0) {
        return false;
    }

    bool forbidden = false;
    struct bpf_iter_num iter;
    bpf_iter_num_new(&iter, 0, num_iters);

    while (bpf_iter_num_next(&iter)) {
        struct nlmsghdr current_nlh;

        if (bpf_probe_read_kernel(&current_nlh, sizeof(struct nlmsghdr), nlh) !=
            0) {
            forbidden = true;
            break;
        }

        // many userspace clients send a buffer with one message
        // and trailing bytes.
        // As such, !NLMSG_OK() is not an indicator for "malformed message"
        // Other kernel facilities similarly do
        // while(NLMSG_OK()) { NLMSG_NEXT() }
        // and ignore NLM_F_MULTI
        // See also CVE-2020-10751 and
        // https://code.opensuse.org/kernel/kernel-source/c/62f9940a51463e82675bade0bfcc2d62e8d2f023.patch
        if (!NLMSG_OK(&current_nlh, remaining)) {
            break;
        }

        if (current_nlh.nlmsg_type == NLMSG_DONE) {
            break;
        }

        if (!is_readonly_rtnl_type(current_nlh.nlmsg_type)) {
            forbidden = true;
            break;
        }

        nlh = NLMSG_NEXT(nlh, remaining);

        // technically == 0 suffices, but I don't trust netlink to not underflow
        // here...
        if (remaining <= 0) {
            break;
        }
    }

    bpf_iter_num_destroy(&iter);

    return forbidden;
}
