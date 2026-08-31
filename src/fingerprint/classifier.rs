use crate::engine::scanner::HostResult;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceRole {
    GatewayRouter,
    Switch,
    Workstation,
    SmartDevice,
    GenericHost,
}

impl DeviceRole {
    pub fn icon(&self) -> &'static str {
        match self {
            DeviceRole::GatewayRouter => "📡",
            DeviceRole::Switch => "🔀",
            DeviceRole::Workstation => "💻",
            DeviceRole::SmartDevice => "🔌",
            DeviceRole::GenericHost => "❓",
        }
    }

    pub fn category_name(&self) -> &'static str {
        match self {
            DeviceRole::GatewayRouter => "Gateways & Routers",
            DeviceRole::Switch => "Managed Switches & Infrastructure",
            DeviceRole::Workstation => "Workstations, Laptops & Servers",
            DeviceRole::SmartDevice => "IoT & Connected Smart Devices",
            DeviceRole::GenericHost => "Other Active Hosts",
        }
    }
}

/// Classifies a host into a primary device role using hostname, IP, vendor, and open ports
pub fn classify_host(host: &HostResult, is_default_gateway: bool) -> DeviceRole {
    let hostname_lower = host
        .hostname
        .as_deref()
        .map(|s| s.to_lowercase())
        .unwrap_or_default();
    let vendor_lower = host
        .vendor
        .as_deref()
        .map(|s| s.to_lowercase())
        .unwrap_or_default();
    let has_ssh = host.open_ports.iter().any(|p| p.port == 22);
    let has_http_or_https = host.open_ports.iter().any(|p| p.port == 80 || p.port == 443);
    let octets = host.ip.octets();
    let last_octet = octets[3];

    // 1. Gateway / Router Identification
    if is_default_gateway
        || (last_octet == 1 || last_octet == 254)
            && (vendor_lower.contains("linksys")
                || vendor_lower.contains("cisco")
                || vendor_lower.contains("netgear")
                || vendor_lower.contains("mikrotik")
                || vendor_lower.contains("tp-link")
                || vendor_lower.contains("ubiquiti")
                || hostname_lower.contains("router")
                || hostname_lower.contains("gateway")
                || hostname_lower.contains("linksys")
                || has_http_or_https)
    {
        return DeviceRole::GatewayRouter;
    }

    // 2. Switch Identification
    if hostname_lower.contains("switch")
        || hostname_lower.contains("sw-")
        || hostname_lower.contains("bridge")
    {
        return DeviceRole::Switch;
    }

    // 3. IoT & Smart Devices
    if vendor_lower.contains("tuya")
        || vendor_lower.contains("xiaomi")
        || vendor_lower.contains("smartmi")
        || vendor_lower.contains("positive grid")
        || vendor_lower.contains("spark")
        || vendor_lower.contains("espressif")
        || vendor_lower.contains("sonos")
        || vendor_lower.contains("roku")
        || vendor_lower.contains("amazon")
        || vendor_lower.contains("philips")
        || hostname_lower.contains("fan")
        || hostname_lower.contains("miapd")
        || hostname_lower.contains("spark")
        || hostname_lower.contains("light")
        || hostname_lower.contains("bulb")
        || hostname_lower.contains("plug")
        || hostname_lower.contains("cam")
        || hostname_lower.contains("tv")
        || hostname_lower.contains("speaker")
        || hostname_lower.contains("room")
    {
        return DeviceRole::SmartDevice;
    }

    // 4. Workstations, Laptops & Servers
    if hostname_lower.contains("mac")
        || hostname_lower.contains("air")
        || hostname_lower.contains("mini")
        || hostname_lower.contains("pro")
        || hostname_lower.contains("pc")
        || hostname_lower.contains("desktop")
        || hostname_lower.contains("laptop")
        || hostname_lower.contains("server")
        || hostname_lower.contains("thinkpad")
        || hostname_lower.contains("dell")
        || hostname_lower.contains("ubuntu")
        || hostname_lower.contains("debian")
        || has_ssh
    {
        return DeviceRole::Workstation;
    }

    DeviceRole::GenericHost
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_classify_router() {
        let host = HostResult {
            ip: Ipv4Addr::new(192, 168, 1, 1),
            is_alive: true,
            hostname: Some("linksys07877".to_string()),
            mac_address: Some("74:12:13:14:75:dc".to_string()),
            vendor: Some("Linksys".to_string()),
            open_ports: Vec::new(),
            min_latency: None,
        };
        assert_eq!(classify_host(&host, true), DeviceRole::GatewayRouter);
    }

    #[test]
    fn test_classify_workstation() {
        let host = HostResult {
            ip: Ipv4Addr::new(192, 168, 1, 202),
            is_alive: true,
            hostname: Some("mac-mini".to_string()),
            mac_address: Some("d4:dc:cd:f2:90:30".to_string()),
            vendor: Some("Apple".to_string()),
            open_ports: Vec::new(),
            min_latency: None,
        };
        assert_eq!(classify_host(&host, false), DeviceRole::Workstation);
    }

    #[test]
    fn test_classify_smart_device() {
        let host = HostResult {
            ip: Ipv4Addr::new(192, 168, 1, 166),
            is_alive: true,
            hostname: Some("dmaker-fan-p30_miapd143".to_string()),
            mac_address: Some("7c:c2:94:a1:d1:43".to_string()),
            vendor: Some("Xiaomi / Smartmi".to_string()),
            open_ports: Vec::new(),
            min_latency: None,
        };
        assert_eq!(classify_host(&host, false), DeviceRole::SmartDevice);
    }
}
