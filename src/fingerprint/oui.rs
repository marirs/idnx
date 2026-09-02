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
    /// Which IEEE registry the assignment came from, when known.
    pub registry: Option<String>,
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
            registry: None,
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
            registry: None,
            source: None,
            is_randomized: true,
        };
    }

    // The cached registry first, longest prefix wins, so a 36-bit MA-S assignment beats
    // the 24-bit block it sits inside.
    if let Some(found) = lookup_in_cache(&bytes) {
        return OuiInfo {
            vendor: Some(found.organization),
            registry: Some(found.registry),
            source: Some(VendorSource::IeeeRegistry),
            is_randomized,
        };
    }

    match macaddr_ouidb::OUI_DB.lookup(bytes) {
        Some(name) => OuiInfo {
            vendor: Some(name.to_string()),
            registry: None,
            source: Some(VendorSource::BundledSnapshot),
            is_randomized,
        },
        None => OuiInfo {
            vendor: None,
            registry: None,
            source: None,
            is_randomized,
        },
    }
}

/// Longest-prefix lookup against the cached IEEE registry: 36-bit, then 28-bit, then 24-bit.
fn lookup_in_cache(bytes: &[u8; 6]) -> Option<Assignment> {
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

    // Longest prefix wins: a 36-bit MA-S assignment beats the 28-bit and 24-bit blocks it
    // sits inside, which matters because those larger blocks are shared.
    for bits in [36u32, 28, 24] {
        let key = value & (!0u64 << (48 - bits)) & 0xFFFF_FFFF_FFFF;
        if let Some(found) = index.get(&(bits, key)) {
            return Some(found.clone());
        }
    }
    None
}

/// The cached registry, parsed once per process.
///
/// Re-reading and rescanning a multi-megabyte registry on every lookup made a scan of a
/// populated neighbour table quadratic; it is parsed once into a map instead.
fn ieee_cache_index() -> &'static HashMap<(u32, u64), Assignment> {
    static CACHE: OnceLock<HashMap<(u32, u64), Assignment>> = OnceLock::new();
    CACHE.get_or_init(|| {
        let mut map = HashMap::new();
        let Some(path) = get_oui_cache_path() else {
            return map;
        };
        let Ok(content) = std::fs::read_to_string(&path) else {
            return map;
        };
        // The cache is written as CSV; the text form is accepted so an older cache written
        // by a previous version still resolves rather than silently returning nothing.
        if content.contains("Registry,Assignment") {
            parse_ieee_csv(&content, &mut map);
        } else {
            parse_ieee_text(&content, &mut map, "MA-L");
        }
        map
    })
}

/// One registry assignment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assignment {
    /// Exact organization name as registered.
    pub organization: String,
    /// `MA-L`, `MA-M` or `MA-S`.
    pub registry: String,
}

/// Parses the official IEEE CSV feeds.
///
/// The CSV is unambiguous in a way the text form is not: `Assignment` carries exactly the
/// significant hex digits, so its length gives the prefix length directly -- 6 digits for
/// MA-L (24 bits), 7 for MA-M (28), 9 for MA-S (36).
pub fn parse_ieee_csv(content: &str, map: &mut HashMap<(u32, u64), Assignment>) {
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .from_reader(content.as_bytes());

    for record in reader.records().flatten() {
        let (Some(registry), Some(assignment), Some(organization)) =
            (record.get(0), record.get(1), record.get(2))
        else {
            continue;
        };

        let hex: String = assignment
            .chars()
            .filter(|c| c.is_ascii_hexdigit())
            .collect::<String>()
            .to_ascii_uppercase();
        let Some(bits) = prefix_bits_for(hex.len()) else {
            continue;
        };
        let organization = organization.trim();
        if organization.is_empty() {
            continue;
        }

        if let Some(key) = prefix_key(&hex, bits) {
            map.insert(
                (bits, key),
                Assignment {
                    organization: organization.to_string(),
                    registry: registry.trim().to_string(),
                },
            );
        }
    }
}

/// Parses the IEEE plain-text registries.
///
/// The text form splits an assignment across two lines: the `(hex)` line carries only the
/// 24-bit OUI, and the following `(base 16)` line carries the assigned range *within* it.
/// For MA-M and MA-S that 24-bit OUI is shared between several organizations -- the real
/// oui36.txt lists `8C-1F-64` twice, for two different companies -- so reading the `(hex)`
/// line alone both loses the prefix length and attributes every address in the block to
/// whichever organization happened to appear first.
pub fn parse_ieee_text(content: &str, map: &mut HashMap<(u32, u64), Assignment>, registry: &str) {
    let mut current_oui: Option<String> = None;

    for line in content.lines() {
        if let Some((prefix_part, org_part)) = line.split_once("(hex)") {
            let hex: String = prefix_part
                .chars()
                .filter(|c| c.is_ascii_hexdigit())
                .collect::<String>()
                .to_ascii_uppercase();
            if hex.len() != 6 {
                current_oui = None;
                continue;
            }
            current_oui = Some(hex.clone());

            // Only MA-L assigns the whole 24-bit block to one organization.
            if registry.eq_ignore_ascii_case("MA-L") {
                let organization = org_part.trim();
                if !organization.is_empty()
                    && let Some(key) = prefix_key(&hex, 24)
                {
                    map.insert(
                        (24, key),
                        Assignment {
                            organization: organization.to_string(),
                            registry: registry.to_string(),
                        },
                    );
                }
            }
            continue;
        }

        let Some((range_part, org_part)) = line.split_once("(base 16)") else {
            continue;
        };
        let Some(oui) = current_oui.clone() else {
            continue;
        };
        let organization = org_part.trim();
        if organization.is_empty() {
            continue;
        }

        // The range is the lower 24 bits, as START-END. How many leading hex digits the
        // two ends share is exactly how many are fixed by the assignment.
        let range: String = range_part.trim().to_ascii_uppercase();
        let significant = match range.split_once('-') {
            Some((start, end)) => common_prefix_len(start.trim(), end.trim()),
            // A bare value repeats the OUI itself, which is the MA-L shape.
            None => 0,
        };

        let bits = 24 + (significant as u32) * 4;
        let Some(bits) = prefix_bits_for((bits / 4) as usize) else {
            continue;
        };

        let start = range.split('-').next().unwrap_or("");
        let combined = format!("{}{}", oui, &start[..significant.min(start.len())]);
        if let Some(key) = prefix_key(&combined, bits) {
            map.insert(
                (bits, key),
                Assignment {
                    organization: organization.to_string(),
                    registry: registry.to_string(),
                },
            );
        }
    }
}

/// Number of leading characters two strings share.
fn common_prefix_len(a: &str, b: &str) -> usize {
    a.chars().zip(b.chars()).take_while(|(x, y)| x == y).count()
}

/// Maps a count of significant hex digits to a supported prefix length.
fn prefix_bits_for(hex_digits: usize) -> Option<u32> {
    match hex_digits {
        6 => Some(24),
        7 => Some(28),
        9 => Some(36),
        _ => None,
    }
}

/// Builds the lookup key for a prefix of the given bit length.
fn prefix_key(hex: &str, bits: u32) -> Option<u64> {
    let needed = (bits / 4) as usize;
    if hex.len() < needed {
        return None;
    }
    let padded = format!("{:0<12}", &hex[..needed]);
    let value = u64::from_str_radix(&padded, 16).ok()?;
    Some(value & (!0u64 << (48 - bits)) & 0xFFFF_FFFF_FFFF)
}

/// Downloads the IEEE MA-L, MA-M and MA-S registries into the cache.
///
/// Written transactionally: the existing cache is replaced only after all three feeds have
/// been retrieved and parsed. A partial download must never overwrite a good registry.
pub async fn update_oui_database() -> Result<usize, String> {
    let cache_file =
        get_oui_cache_path().ok_or_else(|| "Could not determine cache path".to_string())?;
    if let Some(parent) = cache_file.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create cache directory: {e}"))?;
    }

    const FEEDS: &[&str] = &[
        "https://standards-oui.ieee.org/oui/oui.csv",
        "https://standards-oui.ieee.org/oui28/mam.csv",
        "https://standards-oui.ieee.org/oui36/oui36.csv",
    ];

    let mut combined = String::new();
    for url in FEEDS {
        let output = tokio::process::Command::new("curl")
            .args(["-fsSL", url])
            .output()
            .await
            .map_err(|e| format!("Failed to run curl: {e}"))?;
        if !output.status.success() {
            return Err(format!("Could not retrieve {url}; cache left unchanged"));
        }
        combined.push_str(&String::from_utf8_lossy(&output.stdout));
        combined.push('\n');
    }

    let mut map = HashMap::new();
    parse_ieee_csv(&combined, &mut map);
    if map.is_empty() {
        return Err("Downloaded registries parsed to nothing; cache left unchanged".to_string());
    }

    // Write beside the target and rename, so an interrupted write cannot truncate a good
    // cache into an unusable one.
    let temp = cache_file.with_extension("csv.partial");
    std::fs::write(&temp, &combined).map_err(|e| format!("Failed to write OUI cache: {e}"))?;
    std::fs::rename(&temp, &cache_file).map_err(|e| format!("Failed to install OUI cache: {e}"))?;

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

    /// Copied structurally from the real IEEE CSV feeds.
    ///
    /// 8C1F64 is a shared MA-S block: the registry lists it for several unrelated
    /// organizations, which is exactly why a 24-bit key cannot represent it.
    const REAL_CSV: &str = "\
Registry,Assignment,Organization Name,Organization Address
MA-L,286FB9,\"Nokia Shanghai Bell Co., Ltd.\",No.388 Ning Qiao Road Shanghai CN 201206
MA-L,8C1F64,IEEE Registration Authority,445 Hoes Lane Piscataway NJ US 08554
MA-M,C85CE27,SYNERGY SYSTEMS AND SOLUTIONS,A1526 GREEN FIELDS COLONY Faridabad IN 121001
MA-S,8C1F64AFA,\"DATA ELECTRONIC DEVICES, INC\",32 NORTHWESTERN DR SALEM NH US 03079
MA-S,8C1F649B9,\"QUERCUS TECHNOLOGIES, S.L.\",Av. Onze de Setembre 19 Reus ES 43203
";

    /// Copied structurally from the real IEEE plain-text feeds, where the assignment is
    /// split across a `(hex)` line and a following `(base 16)` range line.
    const REAL_TEXT_MA_S: &str = "\
OUI                                                         Organization
OUI-36/MA-S Range                                           Organization

8C-1F-64   (hex)\t\tDATA ELECTRONIC DEVICES, INC
AFA000-AFAFFF     (base 16)\t\tDATA ELECTRONIC DEVICES, INC
\t\t\t\t32 NORTHWESTERN DR
\t\t\t\tSALEM  NH  03079

8C-1F-64   (hex)\t\tQUERCUS TECHNOLOGIES, S.L.
9B9000-9B9FFF     (base 16)\t\tQUERCUS TECHNOLOGIES, S.L.
";

    fn resolve(map: &HashMap<(u32, u64), Assignment>, mac: &str) -> Option<String> {
        let bytes = parse_mac_bytes(mac)?;
        let value = ((bytes[0] as u64) << 40)
            | ((bytes[1] as u64) << 32)
            | ((bytes[2] as u64) << 24)
            | ((bytes[3] as u64) << 16)
            | ((bytes[4] as u64) << 8)
            | (bytes[5] as u64);
        for bits in [36u32, 28, 24] {
            let key = value & (!0u64 << (48 - bits)) & 0xFFFF_FFFF_FFFF;
            if let Some(found) = map.get(&(bits, key)) {
                return Some(found.organization.clone());
            }
        }
        None
    }

    #[test]
    fn csv_assignment_length_determines_prefix_length() {
        let mut map = HashMap::new();
        parse_ieee_csv(REAL_CSV, &mut map);

        assert!(map.keys().any(|(bits, _)| *bits == 24));
        assert!(map.keys().any(|(bits, _)| *bits == 28));
        assert!(map.keys().any(|(bits, _)| *bits == 36));
    }

    #[test]
    fn a_shared_block_resolves_each_assignee_separately() {
        // The defect this replaces: both MA-S entries collapsed onto one 24-bit key, so
        // every 8C:1F:64 address reported whichever organization was parsed first.
        let mut map = HashMap::new();
        parse_ieee_csv(REAL_CSV, &mut map);

        assert_eq!(
            resolve(&map, "8C:1F:64:AF:A1:23").as_deref(),
            Some("DATA ELECTRONIC DEVICES, INC")
        );
        assert_eq!(
            resolve(&map, "8C:1F:64:9B:97:65").as_deref(),
            Some("QUERCUS TECHNOLOGIES, S.L.")
        );
        // An address in the block but outside both MA-S ranges falls back to the registrar.
        assert_eq!(
            resolve(&map, "8C:1F:64:11:22:33").as_deref(),
            Some("IEEE Registration Authority")
        );
    }

    #[test]
    fn ma_m_assignment_resolves_at_28_bits() {
        let mut map = HashMap::new();
        parse_ieee_csv(REAL_CSV, &mut map);

        assert_eq!(
            resolve(&map, "C8:5C:E2:71:23:45").as_deref(),
            Some("SYNERGY SYSTEMS AND SOLUTIONS")
        );
        // Outside the /28, and no /24 covers it.
        assert_eq!(resolve(&map, "C8:5C:E2:01:23:45"), None);
    }

    #[test]
    fn text_format_derives_prefix_length_from_the_base_16_range() {
        // The `(hex)` line carries only the shared 24-bit OUI; the range on the following
        // line is what fixes the remaining digits.
        let mut map = HashMap::new();
        parse_ieee_text(REAL_TEXT_MA_S, &mut map, "MA-S");

        assert!(
            map.keys().all(|(bits, _)| *bits == 36),
            "an MA-S file must not produce 24-bit entries"
        );
        assert_eq!(
            resolve(&map, "8C:1F:64:AF:A0:01").as_deref(),
            Some("DATA ELECTRONIC DEVICES, INC")
        );
        assert_eq!(
            resolve(&map, "8C:1F:64:9B:90:01").as_deref(),
            Some("QUERCUS TECHNOLOGIES, S.L.")
        );
    }

    #[test]
    fn ma_l_text_still_assigns_the_whole_block() {
        let sample = "\
286F-B9 placeholder
28-6F-B9   (hex)\t\tNokia Shanghai Bell Co., Ltd.
286FB9     (base 16)\t\tNokia Shanghai Bell Co., Ltd.
";
        let mut map = HashMap::new();
        parse_ieee_text(sample, &mut map, "MA-L");
        assert_eq!(
            resolve(&map, "28:6F:B9:11:22:33").as_deref(),
            Some("Nokia Shanghai Bell Co., Ltd.")
        );
    }

    #[test]
    fn registry_label_is_retained() {
        let mut map = HashMap::new();
        parse_ieee_csv(REAL_CSV, &mut map);
        assert!(map.values().any(|a| a.registry == "MA-S"));
        assert!(map.values().any(|a| a.registry == "MA-M"));
    }

    #[test]
    fn malformed_registry_lines_are_skipped() {
        let sample = "\
Registry,Assignment,Organization Name,Organization Address
MA-L,ZZZZZZ,Bad Hex,
MA-L,286F,Too Short,
MA-L,38E2CA,Katun Corporation,7760 France Ave S
";
        let mut map = HashMap::new();
        parse_ieee_csv(sample, &mut map);
        assert_eq!(map.len(), 1);
        assert!(map.values().any(|a| a.organization == "Katun Corporation"));
    }

    #[test]
    fn an_unparseable_mac_yields_nothing() {
        let info = lookup_mac("not-a-mac");
        assert!(info.vendor.is_none());
        assert!(!info.is_randomized);
    }
}
