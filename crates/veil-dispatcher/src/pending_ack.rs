//! Re-export shim for the at-least-once delivery tracker.
//!
//! lifted to its own crate
//! [`veil_pending_ack`](veil_pending_ack) so the IPC server can
//! depend on the tracker without importing dispatcher internals. All
//! existing call sites
//! (`crate::pending_ack::PendingAckTracker`
//! `…::AckTickOutcome`) keep compiling unchanged via the re-exports below.

pub use veil_pending_ack::{AckTickOutcome, PendingAckTracker};
