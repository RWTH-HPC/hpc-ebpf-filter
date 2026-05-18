#pragma once

#include <vmlinux.h>

// taken from <linux/netfilter_ipv4/ip_tables.h>

// NOLINTBEGIN

enum IPTablesSockOpt : uint8_t {
    IPT_SO_SET_REPLACE = 64,
    IPT_SO_SET_ADD_COUNTERS = 65,

    // missing the _GET variants, but we currently don't filter those anyways.
};

// NOLINTEND
