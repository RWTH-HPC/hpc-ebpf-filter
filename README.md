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

build via `cargo build --release --locked`.

Note that you must either unset `CC` or export `CC=clang`.

# Compatibility

All of the above is compatible with Rocky9 systems. Newer kernels will likely be compatible (please file issues!).

The filters always fail loudly - the userspace program will exit with an error on incompatible systems.

Note that AF_ALG may be required in some cases - such as util-linux >= 2.38 https://github.com/util-linux/util-linux/pull/4334  
Operators are strongly encouraged to build their own util-linux package with the cryptoapi feature disabled.  
Otherwise, AF_ALG can be reenabled by modifying [filter.bpf.c:deny_socket_create](src/bpf/filter.bpf.c) accordingly.

## Rocky 8

build with `cargo build --release --locked --features rocky8`

There is limited support for Rocky8 systems:

- NETLINK_ROUTE operations are no longer filtered to only allow read-only ops
- The CVE-2026-46333 mitigation won't permit dumping a SUID_DUMP_USER process
