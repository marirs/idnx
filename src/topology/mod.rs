//! Vendor-neutral topology model.
//!
//! `evidence` defines what providers emit, `graph` holds the correlated result, and
//! `role` decides what a device is from what it was observed doing.

pub mod evidence;
pub mod graph;
pub mod realm;
pub mod role;

pub use evidence::{Confidence, DeviceKey, EvidenceSource, Fact, RoleSignal, TopologyEvidence};
pub use graph::{Edge, Node, NodeId, NodeKind, Relationship, TopologyGraph};
pub use role::DeviceRole;
