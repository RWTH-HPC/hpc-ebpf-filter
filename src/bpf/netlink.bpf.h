#pragma once

#include "netlink_defines.h"
#include "rtnetlink_defines.h"
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

// basic operations for links & routes in network namespaces
static __always_inline bool is_allowed_modifying_rtnl_type(u16 message_type) {
    switch (message_type) {
    case RTM_NEWLINK:
    case RTM_DELLINK:
    case RTM_SETLINK:
    case RTM_NEWADDR:
    case RTM_DELADDR:
    case RTM_NEWROUTE:
    case RTM_DELROUTE:
        return true;
    default:
        return false;
    }
}

// clang-format off
/*
// drawn by Gemini 3.1 Pro, because I can't be assed to reverse engineer the netlink code myself
+----------------------------------------------------------------+
| struct nlmsghdr (Netlink Header)                               |
|   nlmsg_len = Total length of everything below inclusive       |
|   nlmsg_type = RTM_NEWLINK                                     |
+----------------------------------------------------------------+
| struct ifinfomsg (Interface Info Header)                       | <--- ifi_ptr points here
|   ifi_family, ifi_type, ifi_index, ifi_flags, etc.             |
+----------------------------------------------------------------+
| Padding (to 4-byte boundary)                                   |
+----------------------------------------------------------------+
| struct rtattr (Routing Attribute 1)                            | <--- rta pointer starts here
|   rta_len = Length of this header + attribute payload          |
|   rta_type = e.g., IFLA_MTU (4)                                |
+----------------------------------------------------------------+
| Attribute Payload 1 (e.g., 4 bytes for MTU size)               |
+----------------------------------------------------------------+
| Padding (to 4-byte boundary)                                   |
+----------------------------------------------------------------+
| struct rtattr (Routing Attribute 2)                            |
|   rta_len                                                      |
|   rta_type = IFLA_LINKINFO (18)                                |
+----------------------------------------------------------------+
| Attribute Payload 2 (Nested rtattr objects)                    | <--- nested pointer starts here
|                                                                |
|   +--------------------------------------------------------+   |
|   | struct nested rtattr i                                 |   |
|   |   rta_len                                              |   |
|   |   rta_type = IFLA_INFO_KIND (1)                        |   |
|   +--------------------------------------------------------+   |
|   | Nested Payload 1 (e.g., "veth\0")                      |   |
|   +--------------------------------------------------------+   |
|                                                                |
|   +--------------------------------------------------------+   |
|   | struct nested rtattr j                                 |   |
|   |   rta_len                                              |   |
|   |   rta_type = IFLA_INFO_DATA (2)                        |   |
|   +--------------------------------------------------------+   |
|   | Nested Payload 2 (More properties for veth...)         |   |
|   +--------------------------------------------------------+   |
+----------------------------------------------------------------+
*/
// clang-format on

static __always_inline bool modifies_veth_or_lo(struct nlmsghdr *nlh,
                                                s64 remaining) {
    // ifinfomsg is only used for these messages, so reject all others
    switch (nlh->nlmsg_type) {
    case RTM_NEWLINK:
    case RTM_DELLINK:
    case RTM_GETLINK:
    case RTM_SETLINK:
        break;
    default:
        return false;
    }
    struct ifinfomsg ifi;
    void *ifi_ptr = NLMSG_DATA(nlh);

    if (bpf_probe_read_kernel(&ifi, sizeof(ifi), ifi_ptr) != 0) {
        return false;
    }

    int attrlen = remaining - NLMSG_SPACE(sizeof(struct ifinfomsg));
    if (attrlen < 0) {
        return false;
    }

    struct rtattr *rta = ifi_ptr + NLMSG_ALIGN(sizeof(struct ifinfomsg));

    struct bpf_iter_num iter;
    bpf_iter_num_new(
        &iter, 0,
        (remaining - sizeof(struct ifinfomsg)) / sizeof(struct rtattr) + 1);

    bool allowed = false;

    while (bpf_iter_num_next(&iter)) {
        struct rtattr current_rta;
        if (bpf_probe_read_kernel(&current_rta, sizeof(struct rtattr), rta) !=
            0) {
            break;
        }

        if (!RTA_OK(&current_rta, attrlen)) {
            break;
        }

        if (current_rta.rta_type == IFLA_LINKINFO) {
            int nested_len =
                current_rta.rta_len - RTA_ALIGN(sizeof(struct rtattr));
            struct rtattr *nested = RTA_DATA(rta);

            struct bpf_iter_num iter_nest;
            bpf_iter_num_new(&iter_nest, 0,
                             nested_len / sizeof(struct rtattr) + 1);

            while (bpf_iter_num_next(&iter_nest)) {
                struct rtattr current_nested;
                if (bpf_probe_read_kernel(&current_nested,
                                          sizeof(struct rtattr), nested) != 0) {
                    break;
                }

                if (!RTA_OK(&current_nested, nested_len)) {
                    break;
                }

                if (current_nested.rta_type == IFLA_INFO_KIND) {
                    char kind[5] = {0};
                    const char *veth_str = "veth";
                    const char *lo_str = "lo";
                    // Ensure length is enough for "veth"
                    int copy_len = current_nested.rta_len -
                                   RTA_ALIGN(sizeof(struct rtattr));
                    if (copy_len >= 5) {
                        if (bpf_probe_read_kernel(kind, 5, RTA_DATA(nested)) ==
                            0) {
                            bool is_veth = true;
                            bool is_lo = true;
                            for (int i = 0; i < 5; i++) {
                                if (kind[i] != veth_str[i]) {
                                    is_veth = false;
                                    break;
                                }
                            }
                            for (int i = 0; i < 3; i++) {
                                if (kind[i] != lo_str[i]) {
                                    is_lo = false;
                                    break;
                                }
                            }
                            if (is_veth || is_lo) {
                                allowed = true;
                            }
                        }
                    }
                    break;
                }

                nested = RTA_NEXT(&current_nested, nested_len);
            }

            bpf_iter_num_destroy(&iter_nest);
            break;
        }

        rta = RTA_NEXT(&current_rta, attrlen);
    }

    bpf_iter_num_destroy(&iter);
    return allowed;
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
        // https://github.com/torvalds/linux/commit/fb73974172ffaaf57a7c42f35424d9aece1a5af6
        if (!NLMSG_OK(&current_nlh, remaining)) {
            break;
        }

        if (current_nlh.nlmsg_type == NLMSG_DONE) {
            break;
        }

        if (!is_readonly_rtnl_type(current_nlh.nlmsg_type) &&
            !is_allowed_modifying_rtnl_type(current_nlh.nlmsg_type)) {
            *message_type = current_nlh.nlmsg_type;
            forbidden = true;
            break;
        }

        if (current_nlh.nlmsg_type == RTM_NEWLINK) {
            // only filter creation
            // subsequent modifying events generally lack the link type,
            // and only use the link index
            if (current_nlh.nlmsg_flags & NLM_F_CREATE) {
                if (!modifies_veth_or_lo(nlh, remaining)) {
                    *message_type = current_nlh.nlmsg_type;
                    forbidden = true;
                    break;
                }
            }
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
