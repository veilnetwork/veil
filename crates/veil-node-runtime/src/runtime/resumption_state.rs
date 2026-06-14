//! H10 stage-B decomposition: session-resumption-domain state
//! extracted into a dedicated [`Arc<ResumptionState>`].
//!
//! ## Why a dedicated struct
//!
//! Pre-stage-B, three structs (`NodeRuntime`, `NodeServices`,
//! `SessionRuntimeContext`) each held two sibling resumption fields
//! (`ticket_issuer` + `peer_tickets`) sprinkled with unrelated session-
//! config knobs. Both are `Arc`-shared Mutex handles populated at
//! startup and never reassigned at runtime, so a dedicated struct
//! collapses a 2-field shared-pair to one typed bundle. Pattern
//! mirrors the established `MailboxState`/`MobileState`/`RoutingState`
//! decomposition: bundle-then-Arc.
//!
//! ## Migration surface
//!
//! Each callsite reading `self.ticket_issuer` / `self.peer_tickets`
//! now reads `self.resumption.ticket_issuer` / `.peer_tickets`. Builder
//! collapses the two `Arc<Mutex<...>>` builder vars into a single
//! `ResumptionState::new` call. No behaviour change.
//!
//! ## Why not to include rekey thresholds
//!
//! `rekey_bytes_threshold` / `rekey_time_threshold_secs` look related
//! but are pure config values (no shared Arc state) and will land in the
//! `SessionDefaults` bundle alongside the other 14 session-knobs in a
//! separate stage. Splitting keeps each bundle's lock-discipline story
//! clean: `ResumptionState` is exclusively two `Arc<Mutex<...>>`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use veil_proto::session::ClientTicketEntry;
use veil_session::ticket::TicketIssuer;

/// Session-resumption-domain state owned by [`crate::node::NodeRuntime`].
pub struct ResumptionState {
    /// host ticket key used to AEAD-encrypt/decrypt session-resumption
    /// tickets. Generated at startup and held for the process lifetime —
    /// periodic rotation is the intended design but is not yet wired (there
    /// is no rotation task or `TICKET_KEY_ROTATION_SECS` const today).
    pub ticket_issuer: Arc<Mutex<TicketIssuer>>,

    /// per-peer session-resumption tickets received from the server.
    /// Maps `peer_id → EncryptedTicket`; presented in the next HELLO TLV
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
