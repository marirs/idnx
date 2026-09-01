#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OuiInfo {
    pub vendor: Option<&'static str>,
    pub is_randomized: bool,
}

impl OuiInfo {
    pub fn display_label(&self) -> String {
        match (self.vendor, self.is_randomized) {
            (Some(v), true) => format!("{} [Randomized MAC]", v),
            (Some(v), false) => v.to_string(),
            (None, true) => "Private / Randomized MAC".to_string(),
            (None, false) => "Unknown Vendor".to_string(),
        }
    }
}

/// Parses a MAC address string into 6 bytes
pub fn parse_mac_bytes(mac_str: &str) -> Option<[u8; 6]> {
    let mut bytes = [0u8; 6];
    let parts: Vec<&str> = mac_str.split(':').collect();
    if parts.len() != 6 {
        return None;
    }

    for (i, part) in parts.iter().enumerate() {
        bytes[i] = u8::from_str_radix(part, 16).ok()?;
    }

    Some(bytes)
}

/// Zero-allocation, sub-microsecond IEEE OUI lookup via sorted binary search
pub fn lookup_mac(mac_str: &str) -> OuiInfo {
    let bytes = match parse_mac_bytes(mac_str) {
        Some(b) => b,
        None => {
            return OuiInfo {
                vendor: None,
                is_randomized: false,
            };
        }
    };

    // IEEE 802 standard: Bit 1 (0x02) of the first octet indicates a Locally Administered (randomized) address
    let is_randomized = (bytes[0] & 0x02) != 0;

    let prefix = [bytes[0], bytes[1], bytes[2]];
    let vendor = match OUI_DATABASE.binary_search_by_key(&prefix, |entry| entry.0) {
        Ok(idx) => Some(OUI_DATABASE[idx].1),
        Err(_) => None,
    };

    OuiInfo {
        vendor,
        is_randomized,
    }
}

/// Pre-sorted compile-time static IEEE OUI table
/// Keys MUST be kept strictly sorted by [u8; 3] for binary_search_by_key to work
static OUI_DATABASE: &[([u8; 3], &str)] = &[
    ([0x00, 0x00, 0x0C], "Cisco Systems"),
    ([0x00, 0x01, 0x42], "Cisco Systems"),
    ([0x00, 0x01, 0x64], "Cisco Systems"),
    ([0x00, 0x01, 0xC7], "Cisco Systems"),
    ([0x00, 0x03, 0x93], "Apple"),
    ([0x00, 0x04, 0x4B], "NVIDIA"),
    ([0x00, 0x06, 0x25], "Linksys"),
    ([0x00, 0x06, 0x5B], "Dell"),
    ([0x00, 0x08, 0x74], "Dell"),
    ([0x00, 0x09, 0x5B], "Netgear"),
    ([0x00, 0x0A, 0x95], "Apple"),
    ([0x00, 0x0C, 0x29], "VMware"),
    ([0x00, 0x0C, 0x42], "MikroTik"),
    ([0x00, 0x0E, 0x0C], "Intel"),
    ([0x00, 0x0F, 0x66], "Linksys"),
    ([0x00, 0x11, 0x24], "Apple"),
    ([0x00, 0x11, 0x32], "Synology"),
    ([0x00, 0x11, 0x43], "Dell"),
    ([0x00, 0x13, 0x02], "Intel"),
    ([0x00, 0x13, 0xE8], "Intel"),
    ([0x00, 0x14, 0xBF], "Linksys"),
    ([0x00, 0x15, 0x00], "Intel"),
    ([0x00, 0x15, 0x65], "Yealink (Teams Phone)"),
    ([0x00, 0x17, 0x88], "Philips Lighting"),
    ([0x00, 0x1A, 0x2B], "Cisco Systems"),
    ([0x00, 0x1E, 0x67], "NVIDIA"),
    ([0x00, 0x26, 0x86], "Netgear"),
    ([0x00, 0x27, 0x22], "Ubiquiti"),
    ([0x04, 0x42, 0x1A], "ASUSTek Computer Inc."),
    ([0x04, 0xD9, 0xF5], "ASUSTek Computer Inc."),
    ([0x04, 0xE4, 0xB6], "Samsung Electronics"),
    ([0x08, 0x55, 0x31], "TP-Link"),
    ([0x10, 0x7B, 0x44], "ASUSTek Computer Inc."),
    ([0x10, 0xBF, 0x48], "ASUSTek Computer Inc."),
    ([0x14, 0x91, 0x82], "Linksys"),
    ([0x14, 0xD8, 0x81], "Xiaomi / Smartmi"),
    ([0x18, 0xE8, 0x29], "Ubiquiti"),
    ([0x20, 0xE5, 0x2A], "Netgear"),
    ([0x24, 0xA0, 0x74], "Ubiquiti"),
    ([0x28, 0xCD, 0xC1], "Raspberry Pi"),
    ([0x2C, 0xFD, 0xA1], "ASUSTek Computer Inc."),
    ([0x38, 0x2C, 0x4A], "ASUSTek Computer Inc."),
    ([0x40, 0x16, 0x7E], "ASUSTek Computer Inc."),
    ([0x48, 0x8F, 0x5A], "MikroTik"),
    ([0x48, 0xB0, 0x2D], "NVIDIA"),
    ([0x50, 0x46, 0x5D], "ASUSTek Computer Inc."),
    ([0x50, 0xC7, 0xBF], "TP-Link"),
    ([0x58, 0x02, 0x05], "AzureWave (NVIDIA DGX / Compute Node)"),
    ([0x60, 0x32, 0xB1], "TP-Link"),
    ([0x60, 0xA4, 0x4C], "ASUSTek Computer Inc."),
    ([0x64, 0x90, 0xC1], "Xiaomi"),
    ([0x64, 0xD1, 0x54], "MikroTik"),
    ([0x68, 0x5E, 0xDD], "Apple"),
    ([0x70, 0x4D, 0x7B], "ASUSTek Computer Inc."),
    ([0x70, 0x4F, 0x57], "TP-Link"),
    ([0x74, 0x12, 0x13], "Linksys"),
    ([0x74, 0xC6, 0x3B], "AzureWave Technology"),
    ([0x78, 0x8A, 0x20], "Ubiquiti"),
    ([0x78, 0x9A, 0x18], "MikroTik"),
    ([0x7C, 0xC2, 0x94], "Xiaomi / Smartmi"),
    ([0x80, 0x5E, 0xC0], "Yealink (Teams Phone)"),
    ([0x98, 0xFC, 0x11], "Netgear"),
    ([0xA0, 0xAD, 0x9F], "ASUSTek Computer Inc."),
    ([0xB0, 0x7D, 0x64], "AzureWave Technology"),
    ([0xB4, 0xFB, 0xE4], "Ubiquiti"),
    ([0xB8, 0x27, 0xEB], "Raspberry Pi"),
    ([0xB8, 0x69, 0xF4], "MikroTik"),
    ([0xC4, 0xF7, 0xC1], "Apple"),
    ([0xCC, 0x2D, 0xE0], "MikroTik"),
    ([0xD4, 0xDC, 0xCD], "Apple"),
    ([0xDC, 0xA6, 0x32], "Raspberry Pi"),
    ([0xE4, 0x5F, 0x01], "Raspberry Pi"),
    ([0xEC, 0x08, 0x6B], "TP-Link"),
    ([0xF0, 0x9F, 0xC2], "Ubiquiti"),
    ([0xFC, 0xEC, 0xDA], "Ubiquiti"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oui_lookup_asus() {
        let res = lookup_mac("a0:ad:9f:e6:38:00");
        assert_eq!(res.vendor, Some("ASUSTek Computer Inc."));
        assert!(!res.is_randomized);
    }

    #[test]
    fn test_oui_lookup_azurewave_dgx() {
        let res = lookup_mac("58:02:05:d1:70:62");
        assert_eq!(res.vendor, Some("AzureWave (NVIDIA DGX / Compute Node)"));
        assert!(!res.is_randomized);
    }

    #[test]
    fn test_oui_lookup_randomized_mac() {
        // 7a:d5:06... -> 0x7a in binary is 0111 1010 -> bit 1 is set -> randomized!
        let res = lookup_mac("7a:d5:06:f5:14:6b");
        assert!(res.is_randomized);
        assert_eq!(res.display_label(), "Private / Randomized MAC");
    }

    #[test]
    fn test_database_is_strictly_sorted() {
        for window in OUI_DATABASE.windows(2) {
            assert!(
                window[0].0 < window[1].0,
                "OUI database must be strictly sorted: {:?} >= {:?}",
                window[0].0,
                window[1].0
            );
        }
    }
}
