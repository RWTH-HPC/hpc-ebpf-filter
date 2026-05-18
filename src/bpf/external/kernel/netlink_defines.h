#pragma once

#include <vmlinux.h>

// taken from <linux/netlink.h>

// NOLINTBEGIN

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

/* Flags values */

#define NLM_F_REQUEST 0x01 /* It is request message. 	*/
#define NLM_F_MULTI 0x02   /* Multipart message, terminated by NLMSG_DONE */
#define NLM_F_ACK 0x04     /* Reply with ack, with zero or error code */
#define NLM_F_ECHO 0x08    /* Receive resulting notifications */
#define NLM_F_DUMP_INTR                                                        \
    0x10 /* Dump was inconsistent due to sequence change                       \
          */
#define NLM_F_DUMP_FILTERED 0x20 /* Dump was filtered as requested */

/* Modifiers to GET request */
#define NLM_F_ROOT 0x100   /* specify tree	root	*/
#define NLM_F_MATCH 0x200  /* return all matching	*/
#define NLM_F_ATOMIC 0x400 /* atomic GET		*/
#define NLM_F_DUMP (NLM_F_ROOT | NLM_F_MATCH)

/* Modifiers to NEW request */
#define NLM_F_REPLACE 0x100 /* Override existing		*/
#define NLM_F_EXCL 0x200    /* Do not touch, if it exists	*/
#define NLM_F_CREATE 0x400  /* Create, if it does not exist	*/
#define NLM_F_APPEND 0x800  /* Add to end of list		*/

/* Modifiers to DELETE request */
#define NLM_F_NONREC 0x100 /* Do not delete recursively	*/
#define NLM_F_BULK 0x200   /* Delete multiple objects	*/

/* Flags for ACK message */
#define NLM_F_CAPPED 0x100   /* request was capped */
#define NLM_F_ACK_TLVS 0x200 /* extended ACK TVLs were included */

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

// NOLINTEND
