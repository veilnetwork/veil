//! Re-export shim for the `SessionTxBroadcaster` adapter.
//!
//! Phase 3 prep (veilcore extraction): canonical implementation moved
//! to [`veil_session::glue::SessionTxBroadcaster`] sibling crate so
//! dispatcher can dep on veil-session directly.  This re-export keeps
//! existing call sites (`crate::node::session_glue::*`) compiling
//! unchanged.

pub use veil_session::glue::*;
