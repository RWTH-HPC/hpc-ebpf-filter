#pragma once

// taken from <linux/netlink.h>

#define NETLINK_ROUTE 0     /* Routing/device hook				*/
#define NETLINK_UNUSED 1    /* Unused number				*/
#define NETLINK_USERSOCK 2  /* Reserved for user mode socket protocols 	*/
#define NETLINK_FIREWALL 3  /* Unused number, formerly ip_queue		*/
#define NETLINK_SOCK_DIAG 4 /* socket monitoring				*/
#define NETLINK_NFLOG 5     /* netfilter/iptables ULOG */
#define NETLINK_XFRM 6      /* ipsec */
#define NETLINK_SELINUX 7   /* SELinux event notifications */
#define NETLINK_ISCSI 8     /* Open-iSCSI */
#define NETLINK_AUDIT 9     /* auditing */
#define NETLINK_FIB_LOOKUP 10
#define NETLINK_CONNECTOR 11
#define NETLINK_NETFILTER 12 /* netfilter subsystem */
#define NETLINK_IP6_FW 13
#define NETLINK_DNRTMSG 14        /* DECnet routing messages */
#define NETLINK_KOBJECT_UEVENT 15 /* Kernel messages to userspace */
#define NETLINK_GENERIC 16
/* leave room for NETLINK_DM (DM Events) */
#define NETLINK_SCSITRANSPORT 18 /* SCSI Transports */
#define NETLINK_ECRYPTFS 19
#define NETLINK_RDMA 20
#define NETLINK_CRYPTO 21 /* Crypto layer */
#define NETLINK_SMC 22    /* SMC monitoring */
