#pragma once

#include "iptables_defines.h"
#include "netlink_defines.h"
#include "shared_base.h" // IWYU pragma: keep
#include "socket_defines.h"

enum Operation : uint8_t {
    SOCKET_CREATE,
    SETSOCKOPT,
    NETLINK_SEND,
};

union OperationDetails {
    struct {
        enum AddressFamily family;
        uint8_t type;
        union {
            enum NetlinkFamily netlink_family;
        } protocol;
    } socket_create;
    struct {
        enum IPTablesSockOpt optname;
    } setsockopt;
    struct __attribute__((packed)) {
        enum NetlinkFamily family;
        uint16_t message_type;
    } netlink_send;
};

struct Event {
    uint32_t pid;
    uint32_t uid;
    enum Operation operation;
    union OperationDetails operation_details;
    unsigned char comm[TASK_COMM_LEN];
};
