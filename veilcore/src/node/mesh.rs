//! Re-export shim for the extracted [`veil-mesh`](veil_mesh) crate.
//!
//! the crate split moved the local-LAN mesh layer — beacons
//! realm-scoped UDP broadcast, neighbor table, gateway-bridge for
//! cross-realm traffic — out to a standalone Tier-3 crate. This module
//! preserves the existing `crate::node::mesh::X` import paths so the rest
//! of veilcore does not need a mass find/replace.

pub use veil_mesh::*;
