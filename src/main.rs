use anyhow::Result;
use clap::Parser;
use libbpf_rs::MapHandle;
use libbpf_rs::RingBufferBuilder;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use log::info;
use skel_links_pin_macro::pin_skel_links;
use std::mem::MaybeUninit;
use std::os::fd::BorrowedFd;
use std::path::{Path, PathBuf};
use tokio::io::{Interest, unix::AsyncFd};

mod filter {
    include!(concat!(env!("OUT_DIR"), "/filter.skel.rs"));
}
mod bindings {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    #![allow(dead_code)]
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}
mod allowlist;

use allowlist::{AllowlistWatcher, load_allowlist};
use bindings::*;
use filter::*;

const PIN_DIR: &str = "/sys/fs/bpf/hpc-ebpf-filter";

#[derive(Debug, Parser)]
struct Args {
    #[arg(long)]
    unpin: bool,

    #[arg(long, value_name = "FILE")]
    allowlist: Option<PathBuf>,
}

fn handle_event(data: &[u8]) -> i32 {
    if data.len() < std::mem::size_of::<Event>() {
        return 0;
    }
    // Safety: BPF ringbuf data is aligned to 8 bytes
    // Event requires 4-byte alignment.
    // The length check above guarantees sufficient size.
    let event = unsafe { &*(data.as_ptr() as *const Event) };
    info!(
        "operation denied: op={:?} pid={} uid={} comm={}",
        event.operation,
        event.pid,
        event.uid,
        std::str::from_utf8(&event.comm).unwrap_or("unknown"),
    );
    0
}

fn unpin() -> Result<()> {
    let pin_dir = Path::new(PIN_DIR);
    if pin_dir.exists() {
        std::fs::remove_dir_all(pin_dir)?;
        info!("eBPF program unpinned from {}", PIN_DIR);
    } else {
        info!("No pinned eBPF program found at {}", PIN_DIR);
    }
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let env = env_logger::Env::default().filter_or("RUST_LOG", "info");
    env_logger::init_from_env(env);

    let args = Args::parse();

    if args.unpin {
        return unpin();
    }

    let allowlist_file = args.allowlist;
    let allowed_paths = if let Some(path) = allowlist_file {
        load_allowlist(&path)?
    } else {
        Vec::new()
    };

    let builder = FilterSkelBuilder::default();

    let mut open_object = MaybeUninit::uninit();
    let open_skel = builder.open(&mut open_object)?;
    let mut skel = open_skel.load()?;

    let mut rb_builder = RingBufferBuilder::new();
    rb_builder.add(&skel.maps.EVENTS, handle_event)?;
    let ringbuf = rb_builder.build()?;

    let async_fd = AsyncFd::with_interest(
        unsafe { BorrowedFd::borrow_raw(ringbuf.epoll_fd()) },
        Interest::READABLE,
    )?;

    let map_handle = MapHandle::try_from(&skel.maps.ALLOWED_FILES)?;

    // Initialize allowlist before enabling the filter.
    let _allowlist = AllowlistWatcher::new(allowed_paths, map_handle);

    // Attach the new program first so there is no coverage gap.
    skel.attach()?;

    info!("HPC eBPF filter attached");

    // Now that the new program is active, atomically replace any existing pin.
    let pin_dir = Path::new(PIN_DIR);
    if pin_dir.exists() {
        for entry in std::fs::read_dir(pin_dir)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                std::fs::remove_file(entry.path())?;
                info!(
                    "Removed previously pinned eBPF program at {}",
                    entry.path().display()
                );
            }
        }
    } else {
        std::fs::create_dir(pin_dir)?;
    }

    pin_skel_links!(FilterLinks, skel.links, pin_dir);

    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                break;
            }
            _ = sigterm.recv() => {
                break;
            }
            guard = async_fd.readable() => {
                let mut guard = guard?;
                ringbuf.consume()?;
                guard.clear_ready();
            }
        }
    }

    info!(
        "Userspace exiting, eBPF programs remain pinned at {}",
        PIN_DIR
    );
    Ok(())
}
