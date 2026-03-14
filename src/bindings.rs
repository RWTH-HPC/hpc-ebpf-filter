#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(clippy::upper_case_acronyms)]
#![allow(non_snake_case)]
#![allow(dead_code)]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
include!(concat!(env!("OUT_DIR"), "/bindings_nobpf.rs"));

use std::fmt::{Display, Formatter};

impl Display for Event {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "op={:?}", self.operation)?;

        unsafe {
            match self.operation {
                Operation::SOCKET_CREATE => {
                    let family = self.operation_details.socket_create.family;
                    write!(f, " family={:?}", family)?;

                    if let Some(sock_type) =
                        sock_type::from_repr(self.operation_details.socket_create.type_ as u32)
                    {
                        write!(f, " type={:?}", sock_type)?;
                    } else {
                        write!(f, " type=unknown")?;
                    }

                    if family == AddressFamily::AF_NETLINK {
                        write!(
                            f,
                            " protocol={:?}",
                            self.operation_details.socket_create.protocol.netlink_family
                        )?;
                    }
                }
                Operation::SETSOCKOPT => {
                    write!(
                        f,
                        " optname={:?}",
                        self.operation_details.setsockopt.optname
                    )?;
                }
                Operation::NETLINK_SEND => {
                    let family = self.operation_details.netlink_send.family;

                    write!(f, " family={:?}", family)?;
                    if family == NetlinkFamily::NETLINK_ROUTE {
                        if let Some(message_type) = RtnetlinkMessageType::from_repr(
                            self.operation_details.netlink_send.message_type,
                        ) {
                            write!(f, " type={:?}", message_type)?;
                        } else {
                            write!(f, " type=unknown")?;
                        }
                    }
                }
            }
        }

        write!(
            f,
            " pid={} uid={} comm={}",
            self.pid,
            self.uid,
            std::str::from_utf8(&self.comm).unwrap_or("unknown"),
        )
    }
}
