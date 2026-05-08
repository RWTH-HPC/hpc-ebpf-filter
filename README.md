# HPC eBPF filter

Ein eBPF-Filterprogramm, um Nutzern bestimmte kernel-Operationen zu untersagen.

System-Prozesse (jene mit UID < 1000) werden nicht gefiltert.

## iptables, nftables, sonstiges socket-Zeugs.

Folgendes wird denied:

- iptables socket-Operationen
- netlink-Operationen für:
  - nftables,
  - nflog
  - xfrm (ipsec)
  - jegliche modifizierende NETLINK_ROUTE Operationen, u.a.
    - Anlegen von Links und Routen, außer loopback und veth (für Container)
    - VLANs, Tunnel
    - tc, qdisc
    - Änderung der Neighbor Table (ARP) und Nexthop
- Nutzung von AF_KEY (ipsec)
- Nutzung von AF_PACKET und das veraltete AF_INET mit SOCK_PACKET
- Nutzung des authencesn-ciphers in AF_ALG - CVE-2026-31431

# Nutzung

`hpc-ebpf-filter`

Ausführung braucht root oder alternativ CAP_BPF

Der Filter bleibt aktiv, nachdem das Programm beendet wurde!  
Kann mit `hpc-ebpf-filter --unpin` oder `rm -rf /sys/fs/bpf/hpc-ebpf-filter` deaktiviert werden.

Jegliche denials werden geloggt.

# Dependencies & Kompilieren

## runtime

- libelf
- libz
- libzstd

## build

- header für jene runtime dependencies
- bpftool
- libbpf
- clang mit bpf target
- Rust >= 1.85.0

Anmerkung für's bauen auf dem cluster: clang aus dem Modulsystem hat das bpf target nicht aktiviert.  
Man müsste sich also lokal per container behelfen, oder clang aus den repo-Quellen installieren.

Bauen via `cargo build --release --locked`.  
Die binary linkt dynamisch gegen obige runtime dependencies.  
Statisch wäre bestimmt angenehmer, habe ich noch nicht nach geschaut.

# Rocky 8

Auf Rocky 8 ist der Filter eingeschränkt verfügbar.

Einschränkungen:

- Es werden keine NETLINK_ROUTE - Operationen mehr gefiltert (also insbesondere tc und qdisc)

Bauen via `cargo build --release --locked --features rocky8`
