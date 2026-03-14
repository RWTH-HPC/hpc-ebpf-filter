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
