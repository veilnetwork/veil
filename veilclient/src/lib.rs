//! High-level Rust client SDK for the Veil network.
//!
//! This crate is only functional on Unix platforms (it communicates with the
//! node via a Unix-domain IPC socket).
//!
//! # Stability
//!
//! The following parts of this API are **stable** (no breaking changes without
//! a protocol version bump):
//!
//! * [`VeilClient`], [`AppHandle`], [`IncomingMessage`] — connection and messaging API.
//! * [`VeilStream`] — reliable ordered byte streams.
//! * Network contract constants re-exported in this module (see below).
//! * The IPC protocol itself: `IPC_PROTOCOL_VERSION` / `CLIENT_MIN_VERSION` / `CLIENT_MAX_VERSION`.
//!
//! The following are **experimental** and may change:
//!
//! * Anything in sub-modules not re-exported here.
//! * Stream flow-control internals (window sizes, etc.).
//!
//! # Handling `VERSION_MISMATCH`
//!
//! If the node returns `VERSION_MISMATCH` during the IPC handshake it means the
//! client library is too old or too new for the running node. The correct response
//! is to upgrade either the client library or the node binary so their
//! `IPC_PROTOCOL_VERSION` ranges overlap.
//!
//! # Quick start
//!
//! `VeilClient` is Unix-only — Windows applications use raw IPC frames over
//! the TCP-loopback backend (see `examples/ovl_proto.py` in the repo root).
//!
//! ```no_run
//! # #[cfg(unix)] {
//! # use veilclient::{VeilClient, ClientError};
//! # async fn example() -> Result<(), ClientError> {
//! let mut client = VeilClient::connect("/run/veil/app.sock").await?;
//! let mut handle = client.bind("myapp.example", "rpc", 1).await?;
//!
//! // Send a datagram to a remote endpoint.
//! let dst_node = [0u8; 32]; // target node_id
//! let dst_app_id = [0u8; 32]; // target app_id
//! let dst_endpoint_id = 1u32;
//! handle.send(dst_node, dst_app_id, dst_endpoint_id, b"hello").await?;
//!
//! // Receive incoming messages.
//! while let Some(msg) = handle.recv().await? {
//!     println!("from {:?}: {:?}", msg.src_node_id, msg.data);
//! }
//! # Ok(())
//! # }
//! # }
//! ```
//!
//! # Network contract constants
//!
//! Key protocol limits re-exported here for use by applications without
//! hard-coding magic numbers:
//!
//! | Constant | Value | Meaning |
//! |----------|-------|---------|
//! | [`MAX_RELAY_HOPS`] | 16 | Maximum veil hops before a frame is dropped |
//! | [`MAX_CLOCK_SKEW_SECS`] | 300 | Max timestamp skew accepted by relay nodes (seconds) |
//! | [`MAX_STREAM_SEND_WINDOW`] | 16 MiB | Maximum in-flight bytes per application stream |

#[cfg(unix)]
pub mod client;
pub mod error;
#[cfg(unix)]
pub mod handle;
/// PoW-gated rendezvous initiator client (Slice 4 of the
/// PoW-Gated Rendezvous epic; see `docs/internal/PLAN_POW_GATED_RENDEZVOUS.md`).
/// Cross-platform — pure crypto + signing, no IPC dependency.
pub mod rendezvous;
#[cfg(unix)]
pub mod stream;

#[cfg(unix)]
pub use client::APP_IPC_SEND_PREFIX_BYTES;
#[cfg(unix)]
pub use client::{
    CreateBootstrapInviteReply, JoinBootstrapResult, MailboxBlobInfo, MailboxPutReply,
    MobileStatus, NodeIdentity, OutboxEntryInfo, PairCreateInviteReply, PairFrameReply,
    PairOobReply, PairStatusReply, PeerEntry, RendezvousReplicaInfo, VeilClient,
};
pub use error::ClientError;
#[cfg(unix)]
pub use handle::{AppHandle, AppReceiver, AppSender, IncomingMessage, IncomingStream};
#[cfg(unix)]
pub use stream::VeilStream;

// ── Network contract constants (stable) ──────────────────────────────────────

/// Maximum veil hops a frame may traverse before it is dropped.
///
/// Re-exported [`veilcore::proto::budget::MAX_RELAY_HOPS`].
pub use veilcore::proto::budget::MAX_RELAY_HOPS;

/// Maximum allowed clock skew (seconds) for message timestamps.
///
/// Messages with `created_at > now + MAX_CLOCK_SKEW_SECS` are rejected by
/// relay nodes. Applications that generate messages should ensure their clock
/// is reasonably synchronized.
///
/// Re-exported [`veilcore::proto::budget::MAX_CLOCK_SKEW_SECS`].
pub use veilcore::proto::budget::MAX_CLOCK_SKEW_SECS;

/// Maximum in-flight bytes per application stream (send-side flow control).
///
/// The stream sender stalls when it has sent this many unacknowledged bytes.
/// Applications that write large payloads should be prepared for back-pressure.
///
/// Re-exported [`veilcore::proto::budget::MAX_STREAM_SEND_WINDOW`].
pub use veilcore::proto::budget::MAX_STREAM_SEND_WINDOW;

/// Mobile-lifecycle tier reported via
/// [`VeilClient::set_mobile_background_mode`].
pub use veilcore::proto::MobileBackgroundMode;

/// Coarse network classification reported via
/// [`VeilClient::notify_network_changed`].
pub use veilcore::proto::NetworkKind;

/// Push-envelope status reply из [`VeilClient::set_push_envelope`]
///
pub use veilcore::proto::SetPushEnvelopeStatus;

/// Wake-HMAC envelope status reply из
/// [`VeilClient::set_wake_hmac_envelope`] (Epic 489.10 slice 4.3.4).
pub use veilcore::proto::SetWakeHmacEnvelopeStatus;

/// Mailbox put status.
pub use veilcore::proto::MailboxPutStatus;

/// Hard caps on payload sizes accepted by the mailbox / push paths.
/// FFI layers re-use these to reject oversized caller input before
/// allocating.
pub use veilcore::proto::{
    MAX_MAILBOX_BLOB_BYTES, MAX_MAILBOX_CAPABILITY_TOKEN_BYTES, MAX_PUSH_ENVELOPE_BYTES,
    MAX_WAKE_HMAC_ENVELOPE_BYTES,
};
