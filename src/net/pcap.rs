//! Reading capture files, for fixtures that exercise the whole decoding path.
//!
//! Unit tests hand a decoder the bytes it expects. A capture file is the shape the data
//! actually arrives in: a header whose byte order has to be established, a link type that
//! has to match what the frame decoder assumes, and records whose declared lengths are the
//! only thing separating one frame from the next. Everything between the file and the graph
//! is where a fixture can catch a defect that per-decoder tests cannot.
//!
//! Only Ethernet captures are accepted. A file recorded on a link with different framing is
//! refused by name rather than decoded as though its header were an Ethernet one.

/// Classic libpcap magic, and the same file written by a big-endian writer.
const MAGIC_MICROSECONDS: u32 = 0xa1b2_c3d4;
const MAGIC_MICROSECONDS_SWAPPED: u32 = 0xd4c3_b2a1;
/// The nanosecond-resolution variants, which differ only in timestamp units.
const MAGIC_NANOSECONDS: u32 = 0xa1b2_3c4d;
const MAGIC_NANOSECONDS_SWAPPED: u32 = 0x4d3c_b2a1;

/// `DLT_EN10MB`: the framing every decoder in this crate assumes.
pub const LINKTYPE_ETHERNET: u32 = 1;

/// The fixed 24-byte file header.
const FILE_HEADER_LEN: usize = 24;
/// The 16-byte per-record header.
const RECORD_HEADER_LEN: usize = 16;

/// A capture file's frames, in the order they were recorded.
#[derive(Debug, Clone)]
pub struct Capture {
    pub link_type: u32,
    pub frames: Vec<Vec<u8>>,
}

/// Reads a capture, or explains why it cannot be used.
///
/// Truncation is reported rather than tolerated: a record whose declared length runs past
/// the end of the file means the remaining bytes are not frames, and guessing where the
/// next one starts would manufacture packets.
pub fn read(bytes: &[u8]) -> Result<Capture, String> {
    if bytes.len() < FILE_HEADER_LEN {
        return Err("shorter than a capture file header".to_string());
    }

    let magic = u32::from_le_bytes(bytes[0..4].try_into().expect("four bytes"));
    let swapped = match magic {
        MAGIC_MICROSECONDS | MAGIC_NANOSECONDS => false,
        MAGIC_MICROSECONDS_SWAPPED | MAGIC_NANOSECONDS_SWAPPED => true,
        other => return Err(format!("not a libpcap capture: magic {other:#010x}")),
    };
    let word = |at: usize| -> u32 {
        let raw = bytes[at..at + 4].try_into().expect("four bytes");
        if swapped {
            u32::from_be_bytes(raw)
        } else {
            u32::from_le_bytes(raw)
        }
    };

    let link_type = word(20);
    if link_type != LINKTYPE_ETHERNET {
        return Err(format!(
            "link type {link_type} is not Ethernet (DLT_EN10MB); its frames have a different \
             header and decoding them as Ethernet would read arbitrary bytes as addresses"
        ));
    }
    let snaplen = word(16) as usize;

    let mut frames = Vec::new();
    let mut at = FILE_HEADER_LEN;
    while at < bytes.len() {
        if at + RECORD_HEADER_LEN > bytes.len() {
            return Err(format!("record header truncated at byte {at}"));
        }
        let captured = word(at + 8) as usize;
        let original = word(at + 12) as usize;
        if captured > snaplen.max(captured) || captured > 262_144 {
            return Err(format!(
                "record at byte {at} declares an implausible length"
            ));
        }
        let start = at + RECORD_HEADER_LEN;
        let end = start + captured;
        if end > bytes.len() {
            return Err(format!(
                "record at byte {at} declares {captured} bytes and the file holds {}",
                bytes.len() - start
            ));
        }
        // A frame captured shorter than it was on the wire is kept as captured: the
        // decoders already refuse what they cannot parse, and dropping it would hide the
        // truncation the fixture is testing.
        let _ = original;
        frames.push(bytes[start..end].to_vec());
        at = end;
    }

    Ok(Capture { link_type, frames })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a little-endian microsecond capture around one frame.
    fn capture(link_type: u32, frames: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&MAGIC_MICROSECONDS.to_le_bytes());
        out.extend_from_slice(&2u16.to_le_bytes()); // major
        out.extend_from_slice(&4u16.to_le_bytes()); // minor
        out.extend_from_slice(&0i32.to_le_bytes()); // timezone
        out.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
        out.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
        out.extend_from_slice(&link_type.to_le_bytes());
        for frame in frames {
            out.extend_from_slice(&1u32.to_le_bytes()); // seconds
            out.extend_from_slice(&0u32.to_le_bytes()); // microseconds
            out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
            out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
            out.extend_from_slice(frame);
        }
        out
    }

    #[test]
    fn frames_come_back_in_order_and_intact() {
        let first = [0xaau8; 60];
        let second = [0xbbu8; 42];
        let file = capture(LINKTYPE_ETHERNET, &[&first, &second]);

        let read = read(&file).expect("a valid capture");
        assert_eq!(read.link_type, LINKTYPE_ETHERNET);
        assert_eq!(read.frames.len(), 2);
        assert_eq!(read.frames[0], first);
        assert_eq!(read.frames[1], second);
    }

    #[test]
    fn a_big_endian_writer_produces_the_same_frames() {
        let frame = [0xccu8; 64];
        let mut file = Vec::new();
        file.extend_from_slice(&MAGIC_MICROSECONDS_SWAPPED.to_le_bytes());
        file.extend_from_slice(&2u16.to_be_bytes());
        file.extend_from_slice(&4u16.to_be_bytes());
        file.extend_from_slice(&0i32.to_be_bytes());
        file.extend_from_slice(&0u32.to_be_bytes());
        file.extend_from_slice(&65535u32.to_be_bytes());
        file.extend_from_slice(&LINKTYPE_ETHERNET.to_be_bytes());
        file.extend_from_slice(&1u32.to_be_bytes());
        file.extend_from_slice(&0u32.to_be_bytes());
        file.extend_from_slice(&(frame.len() as u32).to_be_bytes());
        file.extend_from_slice(&(frame.len() as u32).to_be_bytes());
        file.extend_from_slice(&frame);

        let read = read(&file).expect("a byte-swapped capture is still a capture");
        assert_eq!(read.frames, vec![frame.to_vec()]);
    }

    #[test]
    fn a_capture_from_another_link_type_is_refused_by_name() {
        // 105 is DLT_IEEE802_11. Its frames have a different header, and decoding them as
        // Ethernet would read arbitrary bytes as hardware addresses.
        let file = capture(105, &[&[0u8; 60]]);
        let refused = read(&file).expect_err("a non-Ethernet capture must be refused");
        assert!(refused.contains("link type 105"), "{refused}");
        assert!(refused.contains("Ethernet"), "{refused}");
    }

    #[test]
    fn a_truncated_record_is_reported_rather_than_guessed_at() {
        let mut file = capture(LINKTYPE_ETHERNET, &[&[0x11u8; 60]]);
        file.truncate(file.len() - 20);
        let refused = read(&file).expect_err("a truncated record must be refused");
        assert!(refused.contains("declares"), "{refused}");

        // A header cut in half is refused too.
        let mut header_only = capture(LINKTYPE_ETHERNET, &[&[0x22u8; 60]]);
        header_only.truncate(FILE_HEADER_LEN + 8);
        assert!(read(&header_only).is_err());

        // And a file that is not a capture at all.
        assert!(read(b"not a pcap file at all, not even close").is_err());
    }
}
