#pragma once

#include <vmlinux.h>
//
#include "shared.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(key_size, 0);
    __uint(value_size, 0);
    __uint(max_entries, 4096);
} EVENTS SEC(".maps");

static __always_inline bool is_allowed_user(u32 uid) { return uid < 1000; }

// this always ends with a denial, so don't bother inlining it
static __noinline __attribute__((unused)) void
log_event(u32 uid, enum Operation operation, union OperationDetails details) {
    struct Event *event = bpf_ringbuf_reserve(&EVENTS, sizeof(struct Event), 0);
    if (event != NULL) {
        event->pid = bpf_get_current_pid_tgid() >> 32;
        event->uid = uid;
        event->operation = operation;
        event->operation_details = details;
        bpf_get_current_comm(&event->comm, sizeof(event->comm));
        bpf_ringbuf_submit(event, 0);
    }
}
