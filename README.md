# HPC eBPF filter

Ein eBPF-Filterprogramm, um Nutzern bestimmte kernel-Operationen zu untersagen.

System-Prozesse (jene mit UID < 1000) werden nicht gefiltert.

## iptables, nftables, sonstiges socket-Zeugs.

Folgendes wird denied:

- iptables socket-Operationen
- netlink-Operationen für nftables, nflog und xfrm (ipsec)
- Nutzung von AF_PACKET

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
