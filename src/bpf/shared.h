#pragma once

#ifndef __BPF__
#include <stdint.h>
#else
#include "vmlinux.h" // IWYU pragma: keep
#endif

enum Operation : uint8_t {
    OP_CREATE_NETNS = 0,
    OP_SOCKET_CREATE_AF_PACKET = 10,
    OP_SOCKET_CREATE_AF_NETLINK = 11,
    OP_SOCKET_CREATE_AF_NETLINK_NFLOG = 12,
    OP_SOCKET_CREATE_AF_NETLINK_XFRM = 13,
    OP_SOCKET_CREATE_AF_NETLINK_NETFILTER = 14,
    OP_SOCKET_CREATE_AF_KEY = 15,
    OP_SOCKET_CREATE_AF_INET_SOCK_PACKET = 16,
    OP_SETSOCKOPT_IPT_SO_SET_REPLACE = 20,
    OP_SETSOCKOPT_IPT_SO_SET_ADD_COUNTERS = 21,
    OP_NETLINK_SEND_NFLOG = 30,
    OP_NETLINK_SEND_XFRM = 31,
    OP_NETLINK_SEND_NETFILTER = 32,
    OP_NETLINK_SEND_ROUTE_TC = 33,
};

struct Event {
    uint32_t pid;
    uint32_t uid;
    enum Operation operation;
    unsigned char comm[TASK_COMM_LEN];
};
