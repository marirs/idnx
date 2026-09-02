//! Credential-free network providers.
//!
//! These send packets but never authenticate. Each one is optional: a provider that finds
//! nothing reports that it ran and never halts the others.

use super::{DiscoveryContext, DiscoveryProvider, ProviderFuture};

/// Placeholder registry for network providers, populated as each existing probe module is
/// ported onto the provider interface (mDNS, SSDP, MNDP, LLDP/CDP, SNMP, unicast DNS).
pub fn network_providers() -> Vec<Box<dyn DiscoveryProvider>> {
    Vec::new()
}

/// Kept so the module compiles with an explicit, documented empty set rather than an
/// implicit one; removed once the first network provider lands.
#[allow(dead_code)]
fn _unused(_: &DiscoveryContext) -> Option<ProviderFuture<'static>> {
    None
}
