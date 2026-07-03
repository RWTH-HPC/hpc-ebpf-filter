#pragma once

#include <vmlinux.h>
//
#include "common.bpf.h"
#include "external/kernel/drm_defines.h"

#include <asm-generic/errno-base.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Is `file` a DRM character device (/dev/dri/*)? ioctl command numbers are only
// scoped by their 8-bit magic byte, which is a per-subsystem convention rather
// than a guarantee, so we additionally confirm the target device type here to
// avoid tripping on an unrelated driver that reuses the same nr under magic
// 'd'.
static __always_inline bool is_drm_device(struct file *file) {
    const u32 rdev = file->f_inode->i_rdev;
    return (rdev >> DEV_MINORBITS) == DRM_MAJOR;
}

static __always_inline int filter_ioctl(struct file *file, unsigned int cmd) {
    const u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    if (is_allowed_user(uid)) {
        return 0;
    }

    // CVE-2026-46215
    if (_IOC_TYPE(cmd) == DRM_IOCTL_BASE &&
        _IOC_NR(cmd) == DRM_GEM_CHANGE_HANDLE_NR && is_drm_device(file)) {
        log_event(uid, FILE_IOCTL,
                  (union OperationDetails){.file_ioctl = {.cmd = cmd}});
        return -EPERM;
    }

    return 0;
}

SEC("lsm/file_ioctl")
int BPF_PROG(deny_file_ioctl, struct file *file, unsigned int cmd,
             unsigned long arg, int ret) {
    if (ret != 0) {
        return ret;
    }

    return filter_ioctl(file, cmd);
}

// 32-bit userspace on a 64-bit kernel routes through the compat path; the
// command encoding is identical, so apply the same filter.
SEC("lsm/file_ioctl_compat")
int BPF_PROG(deny_file_ioctl_compat, struct file *file, unsigned int cmd,
             unsigned long arg, int ret) {
    if (ret != 0) {
        return ret;
    }

    return filter_ioctl(file, cmd);
}
