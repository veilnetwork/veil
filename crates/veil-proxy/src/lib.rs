//! Veil proxy subsystem — extraction.
//!
//! Three modules:
//! [`socks5`] — RFC 1928 ingress proxy (CONNECT + bounded UDP ASSOCIATE).
//! Pure protocol + socket plumbing — no veil-specific deps; [`ProxyConnector`]
//! is the abstraction over "open a stream to the exit node".
//! [`exit`] — exit proxy: reads `[host_len][host][port]` header from an
//! veil stream, opens TCP or connected UDP sockets to the destination and
//! bridges them. RFC1918 / link-local destinations are denied unless
//! `allow_private` is set; UDP fan-out, queues and amplification are bounded.
//! [`veil_connector`] — `ProxyConnector` impl that opens an OVL1 app
//! stream (APP_OPEN / APP_DATA / APP_CLOSE) to the exit node via the
//! [`veil_types::FrameBroadcaster`] trait.
//!
//! Cross-crate observability is provided by [`ProxyMetrics`] — implemented
//! on `veilcore::node::observability::NodeMetrics` via the same
//! orphan-rule pattern as the other Tier-3 metric traits.

pub mod exit;
pub mod socks5;
pub mod udp;
pub mod veil_connector;

pub use exit::ExitProxy;
pub use socks5::Socks5Proxy;
pub use veil_connector::{
    EXIT_PROXY_APP_ID, EXIT_PROXY_ENDPOINT_ID, PendingReceiptMap, VeilConnector, VeilStreamRxMap,
    run_server_bridge,
};

/// Metrics surface for the proxy subsystem. Implemented by
/// `veilcore::node::observability::NodeMetrics` via a tiny bridge so
/// this crate stays free of observability concretes.
pub trait ProxyMetrics: Send + Sync {
    /// Bump when an exit proxy denies a destination because the resolved
    /// address falls into a forbidden range (RFC1918 / link-local /
    /// loopback / multicast / etc.).
    fn inc_exit_proxy_dest_denied(&self);
    /// Bump when the SOCKS5 listener drops an accepted connection because
    /// the in-flight semaphore is saturated.
    fn inc_socks5_accepts_throttled(&self);
}
