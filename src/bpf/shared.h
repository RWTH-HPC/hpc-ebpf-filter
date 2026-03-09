#pragma once

#ifndef __BPF__
#include <stdint.h>
#else
#include "vmlinux.h" // IWYU pragma: keep
#endif

enum Syscall : uint8_t {
    SC_UNKNOWN = 0,
    UNSHARE = 1,
    CLONE = 2,
    CLONE3 = 3,
};

struct Event {
    uint32_t pid;
    uint32_t uid;
    enum Syscall syscall;
};
