//! NAT Port Mapping Protocol (RFC 6886) gateway probe.
//!
//! Only a NAT gateway answers this, so a reply is direct behavioural evidence that the
//! device performs NAT — obtained with no credentials, and reaching routers that expose no
//! TCP service whatsoever. That is the case this probe exists for: a consumer router with
//! its WAN-side management closed still commonly answers NAT-PMP on its LAN side.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use crate::net::socket::SocketBinding;
use tokio::time::timeout;

/// The port NAT-PMP and PCP both listen on.
pub const NAT_PMP_PORT: u16 = 5351;

/// Result of asking a gateway for its external address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NatPmpResponse {
    /// RFC 6886 result code; 0 is success.
    pub result_code: u16,
    /// The external address, present only on success.
    pub external_address: Option<Ipv4Addr>,
}

/// Builds the "external address request": version 0, opcode 0.
pub fn external_address_request() -> [u8; 2] {
    [0x00, 0x00]
}

/// Parses a NAT-PMP external-address response.
///
/// Layout: version(1) opcode(1) result(2) epoch(4) address(4). The opcode is the request
/// opcode plus 128, which is what distinguishes a real answer from arbitrary UDP noise
/// arriving on the same socket.
pub fn parse_external_address_response(data: &[u8]) -> Option<NatPmpResponse> {
    if data.len() < 12 {
        return None;
    }
    // Version 0 is NAT-PMP. Version 2 is PCP, which uses a different layout entirely.
    if data[0] != 0 {
        return None;
    }
    if data[1] != 128 {
        return None;
    }

    let result_code = ((data[2] as u16) << 8) | data[3] as u16;
    let external_address = if result_code == 0 {
        let addr = Ipv4Addr::new(data[8], data[9], data[10], data[11]);
        // A gateway that has no external address yet reports zeroes rather than failing.
        (!addr.is_unspecified()).then_some(addr)
    } else {
        None
    };

    Some(NatPmpResponse {
        result_code,
        external_address,
    })
}

/// Asks a device whether it is a NAT gateway.
///
/// Returns `Some` when the device answered as one, carrying its external address where it
/// disclosed one. `None` means it did not answer, which is not evidence either way about
/// whether it routes.
pub async fn probe_nat_gateway(
    target: Ipv4Addr,
    binding: &SocketBinding,
    timeout_duration: Duration,
) -> Option<Option<Ipv4Addr>> {
    let destination = SocketAddrV4::new(target, NAT_PMP_PORT);
    let socket = binding
        .udp_socket(&std::net::SocketAddr::V4(destination))
        .await
        .ok()?;

    socket
        .send_to(&external_address_request(), destination)
        .await
        .ok()?;

    let mut buf = [0u8; 64];
    let (len, from) = timeout(timeout_duration, socket.recv_from(&mut buf))
        .await
        .ok()?
        .ok()?;

    // Only accept an answer from the device we asked; a broadcast reply from elsewhere
    // would otherwise be attributed to this target.
    match from {
        std::net::SocketAddr::V4(v4) if *v4.ip() == target => {}
        _ => return None,
    }

    parse_external_address_response(&buf[..len]).map(|r| r.external_address)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(result: u16, addr: [u8; 4]) -> Vec<u8> {
        let mut v = vec![0x00, 128];
        v.extend_from_slice(&result.to_be_bytes());
        v.extend_from_slice(&[0, 0, 0, 42]); // epoch
        v.extend_from_slice(&addr);
        v
    }

    #[test]
    fn request_is_the_two_byte_external_address_opcode() {
        assert_eq!(external_address_request(), [0x00, 0x00]);
    }

    #[test]
    fn a_successful_response_yields_the_external_address() {
        let parsed = parse_external_address_response(&response(0, [203, 0, 113, 7]))
            .expect("valid response");
        assert_eq!(parsed.result_code, 0);
        assert_eq!(parsed.external_address, Some(Ipv4Addr::new(203, 0, 113, 7)));
    }

    #[test]
    fn an_unassigned_external_address_is_not_reported() {
        // A gateway with no WAN lease yet answers with zeroes; that is still a gateway.
        let parsed =
            parse_external_address_response(&response(0, [0, 0, 0, 0])).expect("valid response");
        assert_eq!(parsed.result_code, 0);
        assert!(parsed.external_address.is_none());
    }

    #[test]
    fn a_failure_result_still_identifies_a_gateway() {
        // Result 2 is "network failure". Only a NAT gateway produces this at all.
        let parsed =
            parse_external_address_response(&response(2, [1, 2, 3, 4])).expect("valid response");
        assert_eq!(parsed.result_code, 2);
        assert!(parsed.external_address.is_none());
    }

    #[test]
    fn arbitrary_udp_is_not_mistaken_for_a_gateway() {
        // Wrong opcode: a response must be request opcode + 128.
        let mut wrong_opcode = response(0, [10, 0, 0, 1]);
        wrong_opcode[1] = 0;
        assert!(parse_external_address_response(&wrong_opcode).is_none());

        // PCP (version 2) has a different layout and must not be parsed as NAT-PMP.
        let mut pcp = response(0, [10, 0, 0, 1]);
        pcp[0] = 2;
        assert!(parse_external_address_response(&pcp).is_none());

        assert!(parse_external_address_response(&[]).is_none());
        assert!(parse_external_address_response(&[0u8; 8]).is_none());
    }
}
