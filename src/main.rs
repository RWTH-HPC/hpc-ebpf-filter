use anyhow::Result;
use libbpf_rs::RingBufferBuilder;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use log::info;
use std::mem::MaybeUninit;
use std::os::fd::BorrowedFd;
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

use bindings::*;
use filter::*;

fn handle_event(data: &[u8]) -> i32 {
    if data.len() < std::mem::size_of::<Event>() {
        return 0;
    }
    // Safety: BPF ringbuf data is aligned to 8 bytes
    // Event requires 4-byte alignment.
    // The length check above guarantees sufficient size.
    let event = unsafe { &*(data.as_ptr() as *const Event) };
    let syscall_name = match event.syscall {
        Syscall::UNSHARE => "unshare",
        Syscall::CLONE => "clone",
        Syscall::CLONE3 => "clone3",
        Syscall::SC_UNKNOWN => "unknown",
    };
    info!(
        "CLONE_NEWNET attempted: pid={} uid={} syscall={} comm={}",
        event.pid,
        event.uid,
        syscall_name,
        std::str::from_utf8(&event.comm).unwrap_or("unknown")
    );
    0
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let env = env_logger::Env::default().filter_or("RUST_LOG", "info");
    env_logger::init_from_env(env);

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

    skel.attach()?;

    info!("HPC eBPF filter attached");

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                break;
            }
            guard = async_fd.readable() => {
                let mut guard = guard?;
                ringbuf.consume()?;
                guard.clear_ready();
            }
        }
    }

    Ok(())
}
