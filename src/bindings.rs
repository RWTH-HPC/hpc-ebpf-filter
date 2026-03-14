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
        write!(
            f,
            "op={:?} {} pid={} uid={} comm={}",
            self.operation,
            unsafe {
                match self.operation {
                    Operation::SOCKET_CREATE => match self.operation_details.socket_create.family {
                        AddressFamily::AF_NETLINK => format!(
                            "family={:?} type={} protocol={:?}",
                            self.operation_details.socket_create.family,
                            sock_type::from_repr(self.operation_details.socket_create.type_ as u32)
                                .and_then(|val| format!("{:?}", val).parse().ok())
                                .unwrap_or("unknown".to_string()),
                            self.operation_details.socket_create.protocol.netlink_family
                        ),
                        _ => format!(
                            "family={:?} type={}",
                            self.operation_details.socket_create.family,
                            sock_type::from_repr(self.operation_details.socket_create.type_ as u32)
                                .and_then(|val| format!("{:?}", val).parse().ok())
                                .unwrap_or("unknown".to_string())
                        ),
                    },
                    Operation::SETSOCKOPT => {
                        format!("optname={:?}", self.operation_details.setsockopt.optname)
                    }
                    Operation::NETLINK_SEND => match self.operation_details.netlink_send.family {
                        NetlinkFamily::NETLINK_ROUTE => format!(
                            "family={:?} type={}",
                            self.operation_details.netlink_send.family,
                            RtnetlinkMessageType::from_repr(
                                self.operation_details.netlink_send.message_type
                            )
                            .and_then(|val| format!("{:?}", val).parse().ok())
                            .unwrap_or("unknown".to_string())
                        ),
                        _ => format!("family={:?}", self.operation_details.netlink_send.family),
                    },
                }
            },
            self.pid,
            self.uid,
            std::str::from_utf8(&self.comm).unwrap_or("unknown"),
        )
    }
}
