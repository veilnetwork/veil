//! Re-export shim for the local transport-success registry.
//!
//! the crate split moved [`TransportHintRegistry`]
//! out of veilcore into [`veil_transport::hint_registry`]. The original
//! type was already implementing [`veil_transport::TransportHintSink`]
//! trait used by the transport registry, but its concrete API was leaking
//! into the IPC server (`crate::node::transport_hints::TransportHintRegistry`).
//! Lifting the type to veil-transport eliminates that leak and is a
//! prerequisite for the upcoming veil-ipc extraction.
//!
//! Existing call sites in `veilcore` (`crate::node::transport_hints::*`)
//! continue to compile unchanged via the re-exports below.

pub use veil_transport::hint_registry::{SchemeCounters, TransportHintRegistry};
