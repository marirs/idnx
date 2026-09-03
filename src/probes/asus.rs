//! ASUS Device Discovery (UDP 9999) — protocol audit outstanding, nothing transmitted.
//!
//! This module deliberately contains no probe. An earlier draft broadcast three guessed
//! payloads (`0c 15 00 00`, `IBOX\0\0\0\0`, `INFO`) to `255.255.255.255:9999` and then
//! accepted *any* datagram that arrived on the socket: it checked no header, no opcode,
//! no length and no correlation with the request, split the payload on NULs, called any
//! part beginning `RT-`/`GT-`/`BE` the model and any part longer than three characters
//! without a dot the SSID. Anything on the link answering that port — a different vendor,
//! an unrelated service, a host that simply echoes — would have produced a device address
//! and a router capability signal assembled from arbitrary bytes. That is a fabrication
//! path, not a weak signal, and it is worse than having no adapter at all.
//!
//! Before a probe lands here, known-good captures or authoritative material must establish:
//!
//! - the destination port or ports, including whether UDP 18017 belongs to this protocol
//!   at all or is a separate service that needs its own audit;
//! - the request header, opcode and length;
//! - the reply header, opcode and length;
//! - how a reply correlates with the request and with its sender;
//! - the exact fields and offsets carrying model, MAC, firmware version and address;
//! - defined behaviour for malformed and truncated packets.
//!
//! Until then [`crate::providers::vendor::AsusBroadcast`] reports
//! `BroadcastOutcome::Unavailable` and creates no topology evidence. Reporting the link as
//! silent would be the same overclaim in a quieter voice: nothing was ever sent.

use std::net::Ipv4Addr;

/// The shape a verified parser will return. Retained as the target of the audit above; it
/// has no constructor because no code may produce one from unvalidated bytes.
#[derive(Debug, Clone)]
pub struct AsusRouterDiscovery {
    pub ip: Ipv4Addr,
    pub model_name: Option<String>,
    pub mac_address: Option<String>,
    pub firmware_version: Option<String>,
    pub ssid: Option<String>,
}

/// Why the broadcast is not run, in the words the adapter reports to the operator.
pub const UNVERIFIED_FRAMING: &str = "ASUS UDP 9999 framing is unverified: the request payloads are guesses and the reply \
     parser validates no header, opcode, length or correlation, so any datagram on the link \
     would become a router discovery";
