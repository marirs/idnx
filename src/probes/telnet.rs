//! Telnet banner reading.
//!
//! A telnet server announces itself before it asks for anything. That greeting is often the
//! only place an appliance states its vendor and model, and on the router this was written
//! against it is the only place at all: the web interface has an empty title and no server
//! header, while telnet says "Welcome Visiting Huawei Home Gateway".
//!
//! Strictly read-only, and deliberately incapable of being anything else. It connects,
//! reads what is offered, and closes. No credentials are sent, no commands are issued, and
//! the option negotiation is not even answered -- a server that will not talk to a silent
//! client simply yields nothing, which is a correct outcome rather than a reason to start
//! negotiating.

use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::time::timeout;

use crate::net::endpoint::Endpoint;
use crate::net::socket::SocketBinding;

/// Telnet's interpret-as-command byte.
const IAC: u8 = 255;
/// Negotiation commands that take one option byte after them.
const WILL: u8 = 251;
const DONT: u8 = 254;
/// Subnegotiation start and end.
const SB: u8 = 250;
const SE: u8 = 240;

/// What a telnet server said before asking for anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelnetBanner {
    /// The greeting with negotiation removed, one line per line offered.
    pub lines: Vec<String>,
    /// Whether the server negotiated options, which tells telnet apart from something else
    /// that happens to be listening on the port.
    pub negotiated: bool,
    /// The raw bytes, so a fact drawn from this can be traced to what arrived.
    pub raw: Vec<u8>,
}

impl TelnetBanner {
    /// The greeting as one line, for display.
    pub fn text(&self) -> String {
        self.lines.join(" / ")
    }

    /// The exact bytes, as hex, for the evidence trail.
    pub fn evidence(&self) -> String {
        let hex: String = self.raw.iter().map(|b| format!("{b:02x}")).collect();
        format!("telnet greeting ({} bytes): {hex}", self.raw.len())
    }
}

/// Reads a telnet greeting.
///
/// `None` means nothing was offered, which says only that: plenty of servers wait for the
/// client to speak first.
pub async fn read_banner(
    target: &Endpoint,
    port: u16,
    binding: &SocketBinding,
    timeout_duration: Duration,
) -> Option<TelnetBanner> {
    let mut stream = binding
        .tcp_connect(target.socket_addr(port), timeout_duration)
        .await
        .ok()?;

    // Bounded: a greeting is a few lines, and a server that streams forever must not hold
    // the run open.
    let mut buffer = vec![0u8; 2048];
    let mut filled = 0usize;
    let deadline = tokio::time::Instant::now() + timeout_duration;

    while filled < buffer.len() {
        let remaining = deadline.checked_duration_since(tokio::time::Instant::now())?;
        match timeout(remaining, stream.read(&mut buffer[filled..])).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(read)) => filled += read,
            Ok(Err(_)) => break,
        }
    }

    // Closed without sending anything back. Nothing is written to this socket at any point.
    drop(stream);

    if filled == 0 {
        return None;
    }
    Some(parse_banner(&buffer[..filled]))
}

/// Separates a greeting from telnet's option negotiation.
///
/// Negotiation is binary and interleaved with the text, so printing the raw bytes would put
/// control sequences on a terminal and lose the greeting inside them.
pub fn parse_banner(bytes: &[u8]) -> TelnetBanner {
    let mut text = Vec::with_capacity(bytes.len());
    let mut negotiated = false;
    let mut index = 0usize;

    while index < bytes.len() {
        let byte = bytes[index];
        if byte != IAC {
            text.push(byte);
            index += 1;
            continue;
        }

        negotiated = true;
        let Some(&command) = bytes.get(index + 1) else {
            break;
        };
        index += match command {
            // A doubled IAC is a literal 255 in the data.
            IAC => {
                text.push(IAC);
                2
            }
            // Subnegotiation runs until IAC SE.
            SB => {
                let mut scan = index + 2;
                while scan + 1 < bytes.len() && !(bytes[scan] == IAC && bytes[scan + 1] == SE) {
                    scan += 1;
                }
                (scan + 2).saturating_sub(index).max(2)
            }
            // WILL, WONT, DO and DONT each carry one option byte.
            WILL..=DONT => 3,
            // Any other command is two bytes.
            _ => 2,
        };
    }

    let decoded = String::from_utf8_lossy(&text);
    let lines: Vec<String> = decoded
        .lines()
        .map(|line| crate::text::sanitize(line.trim()))
        .filter(|line| !line.is_empty())
        .collect();

    TelnetBanner {
        lines,
        negotiated,
        raw: bytes.to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The first bytes the router at hop 2 actually sent.
    fn captured() -> Vec<u8> {
        let mut bytes = vec![
            0xff, 0xfb, 0x01, 0xff, 0xfb, 0x03, 0xff, 0xfb, 0x18, 0x0d, 0x0a,
        ];
        bytes.extend_from_slice(b"Welcome Visiting Huawei Home Gateway\r\n");
        bytes.extend_from_slice(b"Copyright by Huawei Technologies Co., Ltd.\r\n");
        bytes
    }

    #[test]
    fn negotiation_is_separated_from_the_greeting() {
        // Interleaved and binary. Printed raw it would put control sequences on a terminal
        // and bury the one line that identifies the device.
        let banner = parse_banner(&captured());
        assert!(banner.negotiated, "IAC WILL sequences were present");
        assert_eq!(
            banner.lines,
            vec![
                "Welcome Visiting Huawei Home Gateway".to_string(),
                "Copyright by Huawei Technologies Co., Ltd.".to_string(),
            ]
        );
        assert!(banner.text().contains("Huawei"));
    }

    #[test]
    fn the_exact_bytes_are_kept() {
        // A fact drawn from a banner has to be traceable to what arrived, not to how it
        // was rendered.
        let banner = parse_banner(&captured());
        assert_eq!(banner.raw, captured());
        let expected = format!("telnet greeting ({} bytes): fffb01", captured().len());
        assert!(
            banner.evidence().starts_with(&expected),
            "{}",
            banner.evidence()
        );
    }

    #[test]
    fn a_doubled_iac_is_literal_data() {
        let banner = parse_banner(&[b'a', IAC, IAC, b'b']);
        assert_eq!(banner.lines, vec!["a\u{fffd}b".to_string()]);
    }

    #[test]
    fn subnegotiation_is_skipped_whole() {
        let mut bytes = vec![IAC, SB, 0x18, 0x00];
        bytes.extend_from_slice(b"xterm");
        bytes.extend_from_slice(&[IAC, SE]);
        bytes.extend_from_slice(b"ready");
        assert_eq!(parse_banner(&bytes).lines, vec!["ready".to_string()]);
    }

    #[test]
    fn a_truncated_negotiation_does_not_run_past_the_end() {
        // Appliances cut connections mid-sequence, and the bytes come from whatever
        // answered.
        for bytes in [
            vec![IAC],
            vec![IAC, WILL],
            vec![IAC, SB, 0x18],
            vec![IAC, SB],
        ] {
            let banner = parse_banner(&bytes);
            assert!(banner.negotiated);
            assert!(banner.lines.is_empty());
        }
    }

    #[test]
    fn control_characters_in_a_greeting_cannot_reach_a_terminal() {
        // The greeting is chosen by the device, and it is printed.
        let mut bytes = b"\x1b[2JWelcome".to_vec();
        bytes.extend_from_slice(b"\r\n");
        let banner = parse_banner(&bytes);
        assert!(!banner.text().contains('\u{1b}'));
        assert!(banner.text().contains("Welcome"));
    }

    #[test]
    fn a_server_that_only_negotiates_yields_no_greeting() {
        // Distinguishable from one that said nothing at all: the negotiation is recorded.
        let banner = parse_banner(&[IAC, WILL, 0x01, IAC, WILL, 0x03]);
        assert!(banner.negotiated);
        assert!(banner.lines.is_empty());
    }
}
