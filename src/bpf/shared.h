#pragma once

#include "external/kernel/iptables_defines.h"
#include "external/kernel/netlink_defines.h"
#include "external/kernel/socket_defines.h"

// only provided as an anon struct in newer kernels
#define TASK_COMM_LEN 16

enum Operation : uint8_t {
    SOCKET_BIND,
    SOCKET_CREATE,
    SETSOCKOPT,
    NETLINK_SEND,
    PTRACE_DUMPABLE_EXPLOIT,
    FILE_IOCTL,
};

// yeah idk, sockaddr_ is a mess
enum BindType : uint8_t {
    BIND_AF_ALG_AUTHENCESN,
};

union OperationDetails {
    struct {
        enum AddressFamily family;
        enum BindType bind_type;
    } socket_bind;
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
    struct {
        // raw ioctl command number: _IOC(dir, type, nr, size)
        uint32_t cmd;
    } file_ioctl;
};

struct Event {
    uint32_t pid;
    uint32_t uid;
    enum Operation operation;
    union OperationDetails operation_details;
    unsigned char comm[TASK_COMM_LEN];
};
