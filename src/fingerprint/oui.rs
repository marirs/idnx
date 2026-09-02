//! MAC address to registered organization lookup.
//!
//! An OUI identifies the organization that registered an address block. That is all. It
//! does not establish that a device is a router, a switch, an access point, a compute node
//! or any other product: the previous hand-written table asserted things like
//! "AzureWave (NVIDIA DGX / Compute Node)" from a prefix registered simply to AzureWave
//! Technology, and being hand-written it could never be corrected by an update.
//!
//! Two tiers, longest match first:
//!
//! 1. The IEEE registry cached on disk, covering MA-L (24-bit), MA-M (28-bit) and MA-S
//!    (36-bit) assignments and preserving the exact registered organization name.
//! 2. A bundled offline snapshot, so a fresh install with no network still identifies
//!    hardware. Its names are normalized short forms rather than the exact registrations.
//!
//! The cache always wins where it has an answer, which is what makes a stale or wrong
//! bundled value correctable.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::OnceLock;

/// Where a vendor attribution came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VendorSource {
    /// The IEEE registry cached on this machine. Exact registered name.
    IeeeRegistry,
    /// The offline snapshot compiled into the binary. Normalized name.
    BundledSnapshot,
}

impl VendorSource {
    pub fn label(&self) -> &'static str {
        match self {
            VendorSource::IeeeRegistry => "IEEE registry",
            VendorSource::BundledSnapshot => "bundled OUI snapshot",
        }
    }
}

/// The result of a lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OuiInfo {
    /// The organization that registered the address block. Never a product or a role.
    pub vendor: Option<String>,
    pub source: Option<VendorSource>,
    /// True for a locally administered address, which identifies no organization at all.
    pub is_randomized: bool,
}

impl OuiInfo {
    pub fn display_label(&self) -> String {
        match (&self.vendor, self.is_randomized) {
            (Some(v), true) => format!("{} [randomized MAC]", v),
            (Some(v), false) => v.clone(),
            (None, true) => "Private / randomized MAC".to_string(),
            (None, false) => "Unknown manufacturer".to_string(),
        }
    }
}

/// Path of the cached IEEE registry.
pub fn get_oui_cache_path() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    let base = std::env::var("LOCALAPPDATA").ok().map(PathBuf::from);

    #[cfg(not(target_os = "windows"))]
    let base = std::env::var("HOME")
        .ok()
        .map(|home| PathBuf::from(home).join(".cache"));

    base.map(|p| p.join("idnx").join("oui.txt"))
}

/// Parses a MAC address into its six octets.
fn parse_mac_bytes(mac: &str) -> Option<[u8; 6]> {
    let cleaned: String = mac
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>();
    if cleaned.len() < 12 {
        return None;
    }
    let mut out = [0u8; 6];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&cleaned[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// Looks up the organization that registered a MAC address's block.
pub fn lookup_mac(mac_str: &str) -> OuiInfo {
    let Some(bytes) = parse_mac_bytes(mac_str) else {
        return OuiInfo {
            vendor: None,
            source: None,
            is_randomized: false,
        };
    };

    // IEEE 802: bit 1 of the first octet marks a locally administered address. Such an
    // address is chosen by the host, so no registry entry describes it.
    let is_randomized = (bytes[0] & 0x02) != 0;

    if is_randomized {
        return OuiInfo {
            vendor: None,
            source: None,
            is_randomized: true,
        };
    }

    // The cached registry first, longest prefix wins, so a 36-bit MA-S assignment beats
    // the 24-bit block it sits inside.
    if let Some(vendor) = lookup_in_cache(&bytes) {
        return OuiInfo {
            vendor: Some(vendor),
            source: Some(VendorSource::IeeeRegistry),
            is_randomized,
        };
    }

    match macaddr_ouidb::OUI_DB.lookup(bytes) {
        Some(name) => OuiInfo {
            vendor: Some(name.to_string()),
            source: Some(VendorSource::BundledSnapshot),
            is_randomized,
        },
        None => OuiInfo {
            vendor: None,
            source: None,
            is_randomized,
        },
    }
}

/// Longest-prefix lookup against the cached IEEE registry: 36-bit, then 28-bit, then 24-bit.
fn lookup_in_cache(bytes: &[u8; 6]) -> Option<String> {
    let index = ieee_cache_index();
    if index.is_empty() {
        return None;
    }

    let as_u64 = |b: &[u8; 6]| -> u64 {
        ((b[0] as u64) << 40)
            | ((b[1] as u64) << 32)
            | ((b[2] as u64) << 24)
            | ((b[3] as u64) << 16)
            | ((b[4] as u64) << 8)
            | (b[5] as u64)
    };
    let value = as_u64(bytes);

    for bits in [36u32, 28, 24] {
        let key = value & (!0u64 << (48 - bits)) & 0xFFFF_FFFF_FFFF;
        if let Some(name) = index.get(&(bits, key)) {
            return Some(name.clone());
        }
    }
    None
}

/// The cached registry, parsed once per process.
///
/// Re-reading and rescanning a multi-megabyte registry on every lookup made a scan of a
/// populated neighbour table quadratic; it is parsed once into a map instead.
fn ieee_cache_index() -> &'static HashMap<(u32, u64), String> {
    static CACHE: OnceLock<HashMap<(u32, u64), String>> = OnceLock::new();
    CACHE.get_or_init(|| {
        let mut map = HashMap::new();
        let Some(path) = get_oui_cache_path() else {
            return map;
        };
        let Ok(content) = std::fs::read_to_string(&path) else {
            return map;
        };
        parse_ieee_registry(&content, &mut map);
        map
    })
}

/// Parses IEEE registry text into prefix-length-aware entries.
///
/// Handles both the MA-L form `AA-BB-CC   (hex)  Organization` and the MA-M/MA-S form
/// `AA-BB-CC-D0-00-00/28   (hex)  Organization`, which is why entries are keyed by prefix
/// length rather than by a bare 24-bit value.
pub fn parse_ieee_registry(content: &str, map: &mut HashMap<(u32, u64), String>) {
    for line in content.lines() {
        let Some((prefix_part, org_part)) = line.split_once("(hex)") else {
            continue;
        };
        let organization = org_part.trim();
        if organization.is_empty() {
            continue;
        }

        let prefix_text = prefix_part.trim();
        let (address_text, bits) = match prefix_text.split_once('/') {
            Some((addr, len)) => match len.trim().parse::<u32>() {
                Ok(b) => (addr, b),
                Err(_) => continue,
            },
            None => (prefix_text, 24),
        };

        let hex: String = address_text
            .chars()
            .filter(|c| c.is_ascii_hexdigit())
            .collect();
        if hex.len() < 6 {
            continue;
        }
        // Pad to a full 48-bit value so every prefix length shares one key space.
        let padded = format!("{:0<12}", &hex[..hex.len().min(12)]);
        let Ok(value) = u64::from_str_radix(&padded, 16) else {
            continue;
        };
        let key = value & (!0u64 << (48 - bits)) & 0xFFFF_FFFF_FFFF;
        map.entry((bits, key))
            .or_insert_with(|| organization.to_string());
    }
}

/// Downloads the IEEE MA-L, MA-M and MA-S registries into the cache.
///
/// Run opportunistically; a failure leaves the bundled snapshot in place and discovery
/// continues unaffected.
pub async fn update_oui_database() -> Result<usize, String> {
    let cache_file =
        get_oui_cache_path().ok_or_else(|| "Could not determine cache path".to_string())?;
    if let Some(parent) = cache_file.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create cache directory: {e}"))?;
    }

    // All three assignment sizes, so a 28- or 36-bit registration is not reported under the
    // larger block it sits inside.
    const SOURCES: &[&str] = &[
        "https://standards-oui.ieee.org/oui/oui.txt",
        "https://standards-oui.ieee.org/oui28/mam.txt",
        "https://standards-oui.ieee.org/oui36/oui36.txt",
    ];

    let mut combined = String::new();
    for url in SOURCES {
        let output = tokio::process::Command::new("curl")
            .args(["-fsSL", url])
            .output()
            .await
            .map_err(|e| format!("Failed to run curl: {e}"))?;
        if output.status.success() {
            combined.push_str(&String::from_utf8_lossy(&output.stdout));
            combined.push('\n');
        }
    }

    if combined.trim().is_empty() {
        return Err("Could not download any IEEE registry".to_string());
    }

    std::fs::write(&cache_file, &combined)
        .map_err(|e| format!("Failed to write OUI cache: {e}"))?;

    let mut map = HashMap::new();
    parse_ieee_registry(&combined, &mut map);
    Ok(map.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_snapshot_reports_the_registered_organization_only() {
        // These are the exact devices on the test network. Each must resolve to the
        // organization that registered the block, with no product claim attached.
        let apple = lookup_mac("c4:f7:c1:0b:7c:69");
        assert!(apple.vendor.as_deref().unwrap().contains("Apple"));

        let azurewave = lookup_mac("58:02:05:d1:70:62");
        let name = azurewave.vendor.as_deref().unwrap();
        assert!(name.contains("AzureWave"));
        assert!(
            !name.contains("DGX") && !name.contains("NVIDIA"),
            "an OUI cannot establish a product; got {name}"
        );

        for asus in ["60:cf:84:37:1b:70", "a0:ad:9f:e6:38:00"] {
            let found = lookup_mac(asus);
            assert!(
                found.vendor.as_deref().unwrap().contains("ASUSTek"),
                "{asus} must resolve to ASUSTek"
            );
        }
    }

    #[test]
    fn no_vendor_name_encodes_a_role_or_product() {
        // A vendor string must never smuggle in a device role.
        for mac in [
            "c4:f7:c1:0b:7c:69",
            "60:cf:84:37:1b:70",
            "58:02:05:d1:70:62",
            "74:12:13:14:75:dc",
        ] {
            let name = lookup_mac(mac).vendor.unwrap_or_default().to_lowercase();
            for forbidden in [
                "router",
                "switch",
                "gateway",
                "access point",
                "compute node",
            ] {
                assert!(
                    !name.contains(forbidden),
                    "{mac} vendor '{name}' must not assert a role"
                );
            }
        }
    }

    #[test]
    fn a_locally_administered_address_identifies_no_organization() {
        let info = lookup_mac("5e:8e:44:c6:c7:da");
        assert!(info.is_randomized);
        assert!(info.vendor.is_none());
        assert_eq!(info.display_label(), "Private / randomized MAC");
    }

    #[test]
    fn registry_parsing_honours_prefix_length() {
        // MA-L, MA-M and MA-S in one file. Each must be keyed by its own prefix length so
        // that longest-match can prefer the more specific registration.
        let sample = "\
00-1A-2B   (hex)\t\tExample MA-L Corp
AA-BB-C0-00-00-00/28   (hex)\t\tExample MA-M Corp
AA-BB-CC-D0-00-00/36   (hex)\t\tExample MA-S Corp
";
        let mut map = HashMap::new();
        parse_ieee_registry(sample, &mut map);

        assert_eq!(map.len(), 3);
        assert!(map.values().any(|v| v == "Example MA-L Corp"));
        assert!(map.keys().any(|(bits, _)| *bits == 28));
        assert!(map.keys().any(|(bits, _)| *bits == 36));
    }

    #[test]
    fn longest_prefix_wins_over_the_enclosing_block() {
        let sample = "\
AA-BB-CC   (hex)\t\tBlock Owner
AA-BB-CC-D0-00-00/36   (hex)\t\tSpecific Assignee
";
        let mut map = HashMap::new();
        parse_ieee_registry(sample, &mut map);

        // A /36 fixes nine nibbles, so this address must begin AA:BB:CC:D0:0_ to fall
        // inside the specific assignment rather than only the enclosing /24.
        let bytes = [0xAA, 0xBB, 0xCC, 0xD0, 0x0A, 0xBC];
        let value = ((bytes[0] as u64) << 40)
            | ((bytes[1] as u64) << 32)
            | ((bytes[2] as u64) << 24)
            | ((bytes[3] as u64) << 16)
            | ((bytes[4] as u64) << 8)
            | (bytes[5] as u64);

        let mut resolved = None;
        for bits in [36u32, 28, 24] {
            let key = value & (!0u64 << (48 - bits)) & 0xFFFF_FFFF_FFFF;
            if let Some(name) = map.get(&(bits, key)) {
                resolved = Some(name.clone());
                break;
            }
        }
        assert_eq!(resolved.as_deref(), Some("Specific Assignee"));

        // An address inside the /24 but outside the /36 falls back to the block owner.
        let outside = [0xAA, 0xBB, 0xCC, 0xD5, 0x11, 0x22];
        let value = ((outside[0] as u64) << 40)
            | ((outside[1] as u64) << 32)
            | ((outside[2] as u64) << 24)
            | ((outside[3] as u64) << 16)
            | ((outside[4] as u64) << 8)
            | (outside[5] as u64);
        let mut resolved = None;
        for bits in [36u32, 28, 24] {
            let key = value & (!0u64 << (48 - bits)) & 0xFFFF_FFFF_FFFF;
            if let Some(name) = map.get(&(bits, key)) {
                resolved = Some(name.clone());
                break;
            }
        }
        assert_eq!(resolved.as_deref(), Some("Block Owner"));
    }

    #[test]
    fn malformed_registry_lines_are_skipped() {
        let sample = "\
not a registry line
ZZ-ZZ-ZZ   (hex)\t\tBad Hex
00-11-22   (hex)\t\t
00-11-33   (hex)\t\tGood Corp
";
        let mut map = HashMap::new();
        parse_ieee_registry(sample, &mut map);
        assert_eq!(map.len(), 1);
        assert!(map.values().any(|v| v == "Good Corp"));
    }

    #[test]
    fn an_unparseable_mac_yields_nothing() {
        let info = lookup_mac("not-a-mac");
        assert!(info.vendor.is_none());
        assert!(!info.is_randomized);
    }
}
