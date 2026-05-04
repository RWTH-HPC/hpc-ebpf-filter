#pragma once

#include "shared_base.h" // IWYU pragma: keep

// taken from <sys/socket.h>

// NOLINTBEGIN

/* Protocol families.  */
#define PF_UNSPEC 0      /* Unspecified.  */
#define PF_LOCAL 1       /* Local to host (pipes and file-domain).  */
#define PF_UNIX PF_LOCAL /* POSIX name for PF_LOCAL.  */
#define PF_FILE PF_LOCAL /* Another non-standard name for PF_LOCAL.  */
#define PF_INET 2        /* IP protocol family.  */
#define PF_AX25 3        /* Amateur Radio AX.25.  */
#define PF_IPX 4         /* Novell Internet Protocol.  */
#define PF_APPLETALK 5   /* Appletalk DDP.  */
#define PF_NETROM 6      /* Amateur radio NetROM.  */
#define PF_BRIDGE 7      /* Multiprotocol bridge.  */
#define PF_ATMPVC 8      /* ATM PVCs.  */
#define PF_X25 9         /* Reserved for X.25 project.  */
#define PF_INET6 10      /* IP version 6.  */
#define PF_ROSE 11       /* Amateur Radio X.25 PLP.  */
#define PF_DECnet 12     /* Reserved for DECnet project.  */
#define PF_NETBEUI 13    /* Reserved for 802.2LLC project.  */
#define PF_SECURITY 14   /* Security callback pseudo AF.  */
#define PF_KEY 15        /* PF_KEY key management API.  */
#define PF_NETLINK 16
#define PF_ROUTE PF_NETLINK /* Alias to emulate 4.4BSD.  */
#define PF_PACKET 17        /* Packet family.  */
#define PF_ASH 18           /* Ash.  */
#define PF_ECONET 19        /* Acorn Econet.  */
#define PF_ATMSVC 20        /* ATM SVCs.  */
#define PF_RDS 21           /* RDS sockets.  */
#define PF_SNA 22           /* Linux SNA Project */
#define PF_IRDA 23          /* IRDA sockets.  */
#define PF_PPPOX 24         /* PPPoX sockets.  */
#define PF_WANPIPE 25       /* Wanpipe API sockets.  */
#define PF_LLC 26           /* Linux LLC.  */
#define PF_IB 27            /* Native InfiniBand address.  */
#define PF_MPLS 28          /* MPLS.  */
#define PF_CAN 29           /* Controller Area Network.  */
#define PF_TIPC 30          /* TIPC sockets.  */
#define PF_BLUETOOTH 31     /* Bluetooth sockets.  */
#define PF_IUCV 32          /* IUCV sockets.  */
#define PF_RXRPC 33         /* RxRPC sockets.  */
#define PF_ISDN 34          /* mISDN sockets.  */
#define PF_PHONET 35        /* Phonet sockets.  */
#define PF_IEEE802154 36    /* IEEE 802.15.4 sockets.  */
#define PF_CAIF 37          /* CAIF sockets.  */
#define PF_ALG 38           /* Algorithm sockets.  */
#define PF_NFC 39           /* NFC sockets.  */
#define PF_VSOCK 40         /* vSockets.  */
#define PF_KCM 41           /* Kernel Connection Multiplexor.  */
#define PF_QIPCRTR 42       /* Qualcomm IPC Router.  */
#define PF_SMC 43           /* SMC sockets.  */
#define PF_XDP 44           /* XDP sockets.  */
#define PF_MCTP 45          /* Management component transport protocol.  */
#define PF_MAX 46           /* For now..  */

/* Address families.  */

enum AddressFamily : uint8_t {
    AF_UNSPEC = PF_UNSPEC,
    // AF_LOCAL = PF_LOCAL,
    AF_UNIX = PF_UNIX,
    // AF_FILE = PF_FILE,
    AF_INET = PF_INET,
    AF_AX25 = PF_AX25,
    AF_IPX = PF_IPX,
    AF_APPLETALK = PF_APPLETALK,
    AF_NETROM = PF_NETROM,
    AF_BRIDGE = PF_BRIDGE,
    AF_ATMPVC = PF_ATMPVC,
    AF_X25 = PF_X25,
    AF_INET6 = PF_INET6,
    AF_ROSE = PF_ROSE,
    AF_DECnet = PF_DECnet,
    AF_NETBEUI = PF_NETBEUI,
    AF_SECURITY = PF_SECURITY,
    AF_KEY = PF_KEY,
    AF_NETLINK = PF_NETLINK,
    // AF_ROUTE = PF_ROUTE,
    AF_PACKET = PF_PACKET,
    AF_ASH = PF_ASH,
    AF_ECONET = PF_ECONET,
    AF_ATMSVC = PF_ATMSVC,
    AF_RDS = PF_RDS,
    AF_SNA = PF_SNA,
    AF_IRDA = PF_IRDA,
    AF_PPPOX = PF_PPPOX,
    AF_WANPIPE = PF_WANPIPE,
    AF_LLC = PF_LLC,
    AF_IB = PF_IB,
    AF_MPLS = PF_MPLS,
    AF_CAN = PF_CAN,
    AF_TIPC = PF_TIPC,
    AF_BLUETOOTH = PF_BLUETOOTH,
    AF_IUCV = PF_IUCV,
    AF_RXRPC = PF_RXRPC,
    AF_ISDN = PF_ISDN,
    AF_PHONET = PF_PHONET,
    AF_IEEE802154 = PF_IEEE802154,
    AF_CAIF = PF_CAIF,
    AF_ALG = PF_ALG,
    AF_NFC = PF_NFC,
    AF_VSOCK = PF_VSOCK,
    AF_KCM = PF_KCM,
    AF_QIPCRTR = PF_QIPCRTR,
    AF_SMC = PF_SMC,
    AF_XDP = PF_XDP,
    AF_MCTP = PF_MCTP,
    // AF_MAX = PF_MAX,
};

/* Socket level values.  Others are defined in the appropriate headers.

   XXX These definitions also should go into the appropriate headers as
   far as they are available.  */
#define SOL_RAW 255
#define SOL_DECNET 261
#define SOL_X25 262
#define SOL_PACKET 263
#define SOL_ATM 264 /* ATM layer (cell level).  */
#define SOL_AAL 265 /* ATM Adaption Layer (packet level).  */
#define SOL_IRDA 266
#define SOL_NETBEUI 267
#define SOL_LLC 268
#define SOL_DCCP 269
#define SOL_NETLINK 270
#define SOL_TIPC 271
#define SOL_RXRPC 272
#define SOL_PPPOL2TP 273
#define SOL_BLUETOOTH 274
#define SOL_PNPIPE 275
#define SOL_RDS 276
#define SOL_IUCV 277
#define SOL_CAIF 278
#define SOL_ALG 279
#define SOL_NFC 280
#define SOL_KCM 281
#define SOL_TLS 282
#define SOL_XDP 283
#define SOL_MPTCP 284
#define SOL_MCTP 285

/* Maximum queue length specifiable by listen.  */
#define SOMAXCONN 4096

// NOLINTEND
