# HPC eBPF filter

An eBPF LSM program to filter user actions on HPC systems.

The aim of this project is to provide mitigations for common privilege escalation exploits in the linux kernel, without requiring operators to disable user namespaces or reboot.

By default, only UIDs >= 1000 are filtered.

## iptables, nftables, iproute, other socket operations

The following socket-related operations get denied:

- iptables
- netlink operations for:
  - nftables
  - nflog
  - xfrm (ipsec)
  - any modifying NETLINK_ROUTE operation (`ip link | ip route ...`), including but not limited to:
    - creation of links and routes, excluding on loopback and veth (this keeps rootless podman networks working)
    - VLANs
    - tc, qdisc
    - ARP and nexthop settings
- usage of AF_PACKET and the deprecated AF_INET + SOCK_PACKET
- usage of authencesn ciphers in AF_ALG - CVE-2026-31431
- usage of any address family that is not:
  - AF_UNSPEC
  - AF_UNIX
  - AF_INET
  - AF_INET6
  - AF_NETLINK
  - AF_IB
  - AF_XDP

## other misc operations

- ptrace-esque operations on dead processes - CVE-2026-46333
- DRM_IOCTL_GEM_CHANGE_HANDLE ioctl - CVE-2026-46215

# Installation

There are prebuilt container images available at `ghcr.io/rwth-hpc/hpc-ebpf-filter:$DISTRO`.  
See [Supported Distributions](#supported-distributions) for the distro tags.  
Execution requires root via `podman run --privileged=true ...`.

There are no prebuilt images for rocky-8.10 due to issues with getting a VM to boot in CI :/

# Usage

`hpc-ebpf-filter`

Execution requires root. The userspace component drops permissions after the eBPF programs are loaded.

The filters remain active even when the userspace component exits!
They can be unloaded by terminating the userspace component and running `hpc-ebpf-filter --unpin` or `rm -rf /sys/fs/bpf/hpc-ebpf-filter`

All denials are logged.

# Dependencies & compilation

## runtime

- libelf
- libz
- libzstd

## build

- headers for the above libraries
- bpftool
- libbpf
- clang with the bpf target enabled
- Rust >= 1.85.0

Build via `cargo build --release --locked`.  
See also [Supported Distributions](#supported-distributions) to compile for a specific distro kernel.

Note that you must either unset `CC` or export `CC=clang`.

# Compatibility

## Supported Distributions

The following distributions are currently tested:

- rocky-10.2
- rocky-10.1
- rocky-9.8
- rocky-9.7
- rocky-9.6
- rocky-8.10
- ubuntu-26.04
- ubuntu-24.04

It is **strongly recommended** to build for the specific distribution via `RUSTFLAGS="--cfg distro=\"$DISTRO\"" cargo build --release --locked`, e.g. `RUSTFLAGS="--cfg distro=\"rocky-8.10\"" ...`.

x86-64 and arm64 are explicitly tested in CI. Other arches are likely to work.

## General

All of the above is compatible with Rocky9 kernels. Newer kernels will likely be compatible (please file issues!).

The filters always fail loudly - the userspace program will exit with an error on incompatible kernels.

Note that AF_ALG may be required in some cases - such as util-linux >= 2.38 https://github.com/util-linux/util-linux/pull/4334  
Operators are strongly encouraged to build their own util-linux package with the cryptoapi feature disabled.  
Otherwise, AF_ALG can be reenabled by modifying [filter.bpf.c:deny_socket_create](src/bpf/filter.bpf.c) accordingly.

## Rocky 8

There is limited support for Rocky8 kernels:

- NETLINK_ROUTE operations are no longer filtered to only allow read-only ops
- The CVE-2026-46333 mitigation won't permit dumping a SUID_DUMP_USER process
