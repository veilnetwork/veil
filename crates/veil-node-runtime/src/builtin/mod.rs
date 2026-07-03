//! Built-in application services hosted by the daemon.
//!
//! Some veil features are best implemented as **app-level services**
//! that run inside the daemon and communicate with remote peers over
//! the same veil app-message routing IPC clients use. The
//! mailbox-relay (T1.4 P5) is the first such service. Future
//! candidates: an echo / latency-probe diagnostic, a time-sync service
//! a peer-sync coordinator that doesn't require app-side glue.
//!
//! ## Why "as an app", not as a dispatcher opcode
//!
//! Inherits all the existing infrastructure for free: DHT routing
//! session multiplexing, retransmits, padding, anonymity-via-onion.
//! Smaller protocol surface — no new `RelayChainMsg` opcode means
//! no dispatcher-state, no correlation-id correlation, no risk to
//! the hot frame-routing path.
//! Mailbox traffic on the wire is indistinguishable from any other
//! app traffic — privacy plus.
//! Apps and the daemon's own services share the same primitives
//! so unit tests for the service layer don't need a network stack.
//!
//! ## Architecture
//!
//! [`BuiltinAppHost`] owns the lifetime of all registered services:
//! At node startup, the runtime calls [`BuiltinAppHost::spawn`] once
//! per service, passing a closure that processes incoming
//! [`AppMessage`]s.
//! Each service registers one or more endpoints via the shared
//! [`AppEndpointRegistry`] and gets back the corresponding mpsc
//! receivers.
//! On shutdown, the runtime calls [`BuiltinAppHost::shutdown`]
//! which signals each service to stop and joins their task handles.
//!
//! Services can stop on their own (return from the closure) — the
//! host treats that as a graceful exit. Panic in a service task is
//! caught by tokio and surfaces as `JoinError` on shutdown; the
//! daemon logs and continues — one service's bug doesn't kill the
//! whole node.

pub mod host;
pub mod mailbox;

pub use host::{BuiltinAppHost, BuiltinEndpoint, ServiceContext, ServiceSpec};
pub use mailbox::{
    MailboxWakeSender, PushTrigger, spawn_mailbox_app_service, spawn_mailbox_wake_listener,
};
