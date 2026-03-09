# HPC eBPF filter

Ein eBPF-Filterprogramm, um Nutzern das erstellen von network namespaces zu untersagen.

System-Prozesse (jener kleiner < 1000) werden nicht gefiltert.

Lässt sich bei Bedarf granularer anpassen.

# Nutzung

`./hpc-ebpf-filter`

Ausführung braucht root oder alternativ CAP_BPF

Der Filter ist nur aktiv, solange das Programm läuft!  
Ließe sich bei Bedarf aber auch persistent implementieren.

Versuche, einen network namespace anzulegen, werden geloggt.

# Dependencies & Kompilieren

## runtime

- libelf
- libz
- libzstd

## build

- header für jene runtime dependencies
- bpftool
- libbpf
- clang
- Rust >= 1.85.0

Bauen via `cargo build --release`.  
Die binary linkt dynamisch gegen obige runtime dependencies.  
Statisch wäre bestimmt angenehmer, habe ich noch nicht nach geschaut.
