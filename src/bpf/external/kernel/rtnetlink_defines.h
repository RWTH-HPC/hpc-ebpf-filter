#pragma once

#include <vmlinux.h>

// taken from <linux/rtnetlink.h>

// NOLINTBEGIN

#define RTNL_FAMILY_IPMR 128
#define RTNL_FAMILY_IP6MR 129
#define RTNL_FAMILY_MAX 129

#define RTM_NR_MSGTYPES (RTM_MAX + 1 - RTM_BASE)
#define RTM_NR_FAMILIES (RTM_NR_MSGTYPES >> 2)
#define RTM_FAM(cmd) (((cmd) - RTM_BASE) >> 2)

#define RTA_ALIGNTO 4U
#define RTA_ALIGN(len) (((len) + RTA_ALIGNTO - 1) & ~(RTA_ALIGNTO - 1))
#define RTA_OK(rta, len)                                                       \
    ((len) >= (int)sizeof(struct rtattr) &&                                    \
     (rta)->rta_len >= sizeof(struct rtattr) && (rta)->rta_len <= (len))
#define RTA_NEXT(rta, attrlen)                                                 \
    ((attrlen) -= RTA_ALIGN((rta)->rta_len),                                   \
     (struct rtattr *)(((char *)(rta)) + RTA_ALIGN((rta)->rta_len)))
#define RTA_LENGTH(len) (RTA_ALIGN(sizeof(struct rtattr)) + (len))
#define RTA_SPACE(len) RTA_ALIGN(RTA_LENGTH(len))
#define RTA_DATA(rta) ((void *)(((char *)(rta)) + RTA_LENGTH(0)))
#define RTA_PAYLOAD(rta) ((int)((rta)->rta_len) - RTA_LENGTH(0))

#define RTN_MAX (__RTN_MAX - 1)

// NOLINTEND
