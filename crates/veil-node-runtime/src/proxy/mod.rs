//! Proxy spawn glue. : socks5 / exit / veil_connector now live
//! in `veil-proxy`; only the integration glue (`tasks.rs`, which constructs
//! the trait-typed deps from runtime concretes) remains here.
//!
//! Existing call sites use `crate::proxy::Socks5Proxy` etc. — these
//! are re-exported from `veil_proxy` via the same path.

pub mod routed_frames;
pub mod tasks;

pub use veil_proxy::{EXIT_PROXY_APP_ID, EXIT_PROXY_ENDPOINT_ID, Socks5Proxy, VeilConnector};

/// Convenience re-exports kept for the existing `crate::proxy::veil_connector::*`
/// import paths sprinkled through dispatcher / runtime wiring.
pub mod veil_connector {
    pub use veil_proxy::veil_connector::{PendingReceiptMap, VeilStreamRxMap, run_server_bridge};
}

pub mod socks5 {
    pub use veil_proxy::socks5::{
        BiStream, ProxyConnector, ProxyDestination, Socks5Error, handle_connection,
    };
}

pub mod exit {
    pub use veil_proxy::exit::handle_proxy_connect_stream_with_metrics;
}
