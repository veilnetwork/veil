//! H10 stage-B decomposition: session-resumption-domain state
//! extracted into а dedicated [`Arc<ResumptionState>`].
//!
//! ## Why а dedicated struct
//!
//! Pre-stage-B, three structs (`NodeRuntime`, `NodeServices`,
//! `SessionRuntimeContext`) each held two sibling resumption fields
//! (`ticket_issuer` + `peer_tickets`) sprinkled с unrelated session-
//! config knobs. Both are `Arc`-shared Mutex handles populated at
//! startup и never reassigned at runtime, so а dedicated struct
//! collapses а 2-field shared-pair to one typed bundle. Pattern
//! mirrors the established `MailboxState`/`MobileState`/`RoutingState`
//! decomposition: bundle-then-Arc.
//!
//! ## Migration surface
//!
//! Each callsite reading `self.ticket_issuer` / `self.peer_tickets`
//! now reads `self.resumption.ticket_issuer` / `.peer_tickets`. Builder
//! collapses the two `Arc<Mutex<...>>` builder vars into а single
//! `ResumptionState::new` call. No behaviour change.
//!
//! ## Why not к include rekey thresholds
//!
//! `rekey_bytes_threshold` / `rekey_time_threshold_secs` look related
//! but are pure config values (no shared Arc state) и will land в the
//! `SessionDefaults` bundle alongside the other 14 session-knobs in а
//! separate stage. Splitting keeps each bundle's lock-discipline story
//! clean: `ResumptionState` is exclusively two `Arc<Mutex<...>>`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use veil_proto::session::ClientTicketEntry;
use veil_session::ticket::TicketIssuer;

/// Session-resumption-domain state owned by [`crate::node::NodeRuntime`].
pub struct ResumptionState {
    /// host ticket key used к AEAD-encrypt/decrypt session-resumption
    /// tickets. Rotated every `TICKET_KEY_ROTATION_SECS` seconds by а
    /// background task.
    pub ticket_issuer: Arc<Mutex<TicketIssuer>>,

    /// per-peer session-resumption tickets received from the server.
    /// Maps `peer_id → EncryptedTicket`; presented в the next HELLO TLV
    /// when reconnecting to the same peer.
    pub peer_tickets: Arc<Mutex<HashMap<[u8; 32], ClientTicketEntry>>>,
}

impl ResumptionState {
    pub fn new(
        ticket_issuer: Arc<Mutex<TicketIssuer>>,
        peer_tickets: Arc<Mutex<HashMap<[u8; 32], ClientTicketEntry>>>,
    ) -> Self {
        Self {
            ticket_issuer,
            peer_tickets,
        }
    }
}
