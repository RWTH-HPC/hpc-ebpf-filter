#pragma once

#include <vmlinux.h>

// ioctl command encoding, from <asm-generic/ioctl.h>

// NOLINTBEGIN

#define _IOC_NRBITS 8
#define _IOC_TYPEBITS 8

#define _IOC_NRSHIFT 0
#define _IOC_TYPESHIFT (_IOC_NRSHIFT + _IOC_NRBITS)

#define _IOC_NRMASK ((1U << _IOC_NRBITS) - 1)
#define _IOC_TYPEMASK ((1U << _IOC_TYPEBITS) - 1)

#define _IOC_NR(cmd) (((cmd) >> _IOC_NRSHIFT) & _IOC_NRMASK)
#define _IOC_TYPE(cmd) (((cmd) >> _IOC_TYPESHIFT) & _IOC_TYPEMASK)

// from <drm/drm.h>: base magic byte for all DRM ioctls
#define DRM_IOCTL_BASE 'd'

// from <uapi/linux/major.h>: major number of DRM character devices (/dev/dri/*)
#define DRM_MAJOR 226

#define DRM_GEM_CHANGE_HANDLE_NR 0xD2

// in-kernel dev_t minor width, from <linux/kdev_t.h>: MAJOR(dev) == dev >> 20
#define DEV_MINORBITS 20

// NOLINTEND
