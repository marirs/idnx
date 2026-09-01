use std::process::Command;

#[derive(Debug, Clone)]
pub struct LinkSpeedInfo {
    pub speed_display: String,
    #[allow(dead_code)]
    pub is_wireless: bool,
}

/// Detects the current negotiated physical or wireless link speed of an interface
pub fn get_interface_link_speed(iface_name: &str) -> Option<LinkSpeedInfo> {
    #[cfg(target_os = "macos")]
    {
        get_macos_link_speed(iface_name)
    }

    #[cfg(target_os = "linux")]
    {
        get_linux_link_speed(iface_name)
    }

    #[cfg(target_os = "windows")]
    {
        get_windows_link_speed(iface_name)
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        None
    }
}

#[cfg(target_os = "macos")]
fn get_macos_link_speed(iface_name: &str) -> Option<LinkSpeedInfo> {
    // 1. Check if it's an active Wi-Fi interface by querying system_profiler
    if let Ok(out) = Command::new("system_profiler")
        .args(["SPAirPortDataType"])
        .output()
    {
        let stdout = String::from_utf8_lossy(&out.stdout);
        if let Some(curr_idx) = stdout.find("Current Network Information:") {
            let section = &stdout[curr_idx..];
            let end_idx = section[28..]
                .find("Other Local Wi-Fi Networks:")
                .map(|i| 28 + i)
                .unwrap_or(section.len());
            let current_info = &section[..end_idx];

            let mut phy_mode = None;
            let mut channel = None;
            let mut tx_rate_mbps: Option<f64> = None;

            for line in current_info.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("PHY Mode:") {
                    phy_mode = Some(trimmed.trim_start_matches("PHY Mode:").trim().to_string());
                } else if trimmed.starts_with("Channel:") {
                    channel = Some(trimmed.trim_start_matches("Channel:").trim().to_string());
                } else if trimmed.starts_with("Transmit Rate:")
                    && let Ok(rate) = trimmed
                        .trim_start_matches("Transmit Rate:")
                        .trim()
                        .parse::<f64>()
                {
                    tx_rate_mbps = Some(rate);
                }
            }

            if let Some(rate) = tx_rate_mbps {
                let speed_str = if rate >= 1000.0 {
                    format!("{:.2} Gbps", rate / 1000.0)
                } else {
                    format!("{:.0} Mbps", rate)
                };

                let mut details = Vec::new();
                if let Some(phy) = phy_mode {
                    let friendly_phy = match phy.as_str() {
                        "802.11ax" => "Wi-Fi 6 / 6E",
                        "802.11be" => "Wi-Fi 7",
                        "802.11ac" => "Wi-Fi 5",
                        _ => &phy,
                    };
                    details.push(friendly_phy.to_string());
                }
                if let Some(ch) = channel {
                    details.push(ch);
                }

                let final_str = if details.is_empty() {
                    speed_str
                } else {
                    format!("{} ({})", speed_str, details.join(", "))
                };

                return Some(LinkSpeedInfo {
                    speed_display: final_str,
                    is_wireless: true,
                });
            }
        }
    }

    // 2. Check if it's an Ethernet interface via `ifconfig <iface>`
    if let Ok(out) = Command::new("ifconfig").arg(iface_name).output() {
        let stdout = String::from_utf8_lossy(&out.stdout);
        for line in stdout.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("media:") {
                // e.g. "media: autoselect (1000baseT <full-duplex>)" or "media: autoselect (10Gbase-T <full-duplex>)"
                if let Some(start) = trimmed.find('(')
                    && let Some(end) = trimmed.find(')')
                {
                    let inner = &trimmed[start + 1..end];
                    let speed_desc = parse_media_speed(inner);
                    return Some(LinkSpeedInfo {
                        speed_display: speed_desc,
                        is_wireless: false,
                    });
                }
            }
        }
    }

    None
}

#[cfg(target_os = "linux")]
fn get_linux_link_speed(iface_name: &str) -> Option<LinkSpeedInfo> {
    // 1. Check Ethernet speed via sysfs: /sys/class/net/<iface>/speed
    let speed_path = format!("/sys/class/net/{}/speed", iface_name);
    if let Ok(speed_str) = std::fs::read_to_string(&speed_path)
        && let Ok(speed_mbps) = speed_str.trim().parse::<u64>()
    {
        let duplex_path = format!("/sys/class/net/{}/duplex", iface_name);
        let duplex_str = std::fs::read_to_string(duplex_path).unwrap_or_default();
        let duplex = if duplex_str.trim().eq_ignore_ascii_case("full") {
            "Full-Duplex"
        } else if duplex_str.trim().eq_ignore_ascii_case("half") {
            "Half-Duplex"
        } else {
            ""
        };

        let formatted_speed = if speed_mbps >= 10000 {
            "10 Gbps".to_string()
        } else if speed_mbps >= 2500 {
            "2.5 Gbps".to_string()
        } else if speed_mbps >= 1000 {
            "1 Gbps".to_string()
        } else {
            format!("{} Mbps", speed_mbps)
        };

        let display = if duplex.is_empty() {
            formatted_speed
        } else {
            format!("{} ({})", formatted_speed, duplex)
        };

        return Some(LinkSpeedInfo {
            speed_display: display,
            is_wireless: false,
        });
    }

    // 2. Check wireless bitrate via `iw dev <iface> link`
    if let Ok(out) = Command::new("iw")
        .args(["dev", iface_name, "link"])
        .output()
    {
        let stdout = String::from_utf8_lossy(&out.stdout);
        for line in stdout.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("tx bitrate:") {
                let rate_str = trimmed.trim_start_matches("tx bitrate:").trim();
                return Some(LinkSpeedInfo {
                    speed_display: format!("{} (Wireless)", rate_str),
                    is_wireless: true,
                });
            }
        }
    }

    None
}

#[cfg(target_os = "windows")]
fn get_windows_link_speed(_iface_name: &str) -> Option<LinkSpeedInfo> {
    if let Ok(out) = Command::new("netsh")
        .args(["wlan", "show", "interfaces"])
        .output()
    {
        let stdout = String::from_utf8_lossy(&out.stdout);
        for line in stdout.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("Transmit rate (Mbps)")
                && let Some(val) = trimmed.split(':').nth(1)
            {
                let rate = val.trim();
                return Some(LinkSpeedInfo {
                    speed_display: format!("{} Mbps (Wi-Fi)", rate),
                    is_wireless: true,
                });
            }
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn parse_media_speed(media_str: &str) -> String {
    let lower = media_str.to_lowercase();
    if lower.contains("10gbase") {
        "10 Gbps (10GBASE-T Full-Duplex)".to_string()
    } else if lower.contains("5000base") || lower.contains("5gbase") {
        "5 Gbps (5GBASE-T Full-Duplex)".to_string()
    } else if lower.contains("2500base") || lower.contains("2.5gbase") {
        "2.5 Gbps (2.5GBASE-T Full-Duplex)".to_string()
    } else if lower.contains("1000base") {
        "1 Gbps (1000BASE-T Full-Duplex)".to_string()
    } else if lower.contains("100base") {
        "100 Mbps (Fast Ethernet)".to_string()
    } else if lower.contains("10base") {
        "10 Mbps (10BASE-T)".to_string()
    } else {
        media_str.to_string()
    }
}
