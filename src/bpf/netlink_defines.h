#pragma once

#include "shared_base.h" // IWYU pragma: keep

// taken from <linux/netlink.h>

enum NetlinkFamily : uint8_t {
    NETLINK_ROUTE = 0,     /* Routing/device hook				*/
    NETLINK_UNUSED = 1,    /* Unused number				*/
    NETLINK_USERSOCK = 2,  /* Reserved for user mode socket protocols 	*/
    NETLINK_FIREWALL = 3,  /* Unused number, formerly ip_queue		*/
    NETLINK_SOCK_DIAG = 4, /* socket monitoring				*/
    NETLINK_NFLOG = 5,     /* netfilter/iptables ULOG */
    NETLINK_XFRM = 6,      /* ipsec */
    NETLINK_SELINUX = 7,   /* SELinux event notifications */
    NETLINK_ISCSI = 8,     /* Open-iSCSI */
    NETLINK_AUDIT = 9,     /* auditing */
    NETLINK_FIB_LOOKUP = 10,
    NETLINK_CONNECTOR = 11,
    NETLINK_NETFILTER = 12, /* netfilter subsystem */
    NETLINK_IP6_FW = 13,
    NETLINK_DNRTMSG = 14,        /* DECnet routing messages */
    NETLINK_KOBJECT_UEVENT = 15, /* Kernel messages to userspace */
    NETLINK_GENERIC = 16,
    /* leave room for NETLINK_DM (DM Events) */
    NETLINK_SCSITRANSPORT = 18, /* SCSI Transports */
    NETLINK_ECRYPTFS = 19,
    NETLINK_RDMA = 20,
    NETLINK_CRYPTO = 21, /* Crypto layer */
    NETLINK_SMC = 22,    /* SMC monitoring */
};

#define NLMSG_ALIGNTO 4U
#define NLMSG_ALIGN(len) (((len) + NLMSG_ALIGNTO - 1) & ~(NLMSG_ALIGNTO - 1))
#define NLMSG_HDRLEN ((int)NLMSG_ALIGN(sizeof(struct nlmsghdr)))
#define NLMSG_LENGTH(len) ((len) + NLMSG_HDRLEN)
#define NLMSG_SPACE(len) NLMSG_ALIGN(NLMSG_LENGTH(len))
#define NLMSG_DATA(nlh) ((void *)(((char *)nlh) + NLMSG_HDRLEN))
#define NLMSG_NEXT(nlh, len)                                                   \
    ((len) -= NLMSG_ALIGN((nlh)->nlmsg_len),                                   \
     (struct nlmsghdr *)(((char *)(nlh)) + NLMSG_ALIGN((nlh)->nlmsg_len)))
#define NLMSG_OK(nlh, len)                                                     \
    ((len) >= (int)sizeof(struct nlmsghdr) &&                                  \
     (nlh)->nlmsg_len >= sizeof(struct nlmsghdr) && (nlh)->nlmsg_len <= (len))
#define NLMSG_PAYLOAD(nlh, len) ((nlh)->nlmsg_len - NLMSG_SPACE((len)))

#define NLMSG_NOOP 0x1    /* Nothing.     */
#define NLMSG_ERROR 0x2   /* Error        */
#define NLMSG_DONE 0x3    /* End of a dump    */
#define NLMSG_OVERRUN 0x4 /* Data lost        */
