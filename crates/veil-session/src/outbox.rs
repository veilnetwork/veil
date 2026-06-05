//! Per-session outbox for request/response-style RPC over OVL1 sessions.
//!
//! `SessionOutbox` is a shared table of `mpsc::Sender<OutboxRequest>` keyed
//! by `peer_id`. Each active `SessionRunner` registers its receiver at
//! startup and drains it alongside the inbound frame loop.
//!
//! An `OutboxRequest` bundles an encoded OVL1 frame with a oneshot sender
//! that the runner uses to deliver the response back to the caller.

use std::collections::HashMap;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};
use veil_util::lock;

use tokio::sync::{mpsc, oneshot};

use veil_cfg::NodeId;

/// A pending outgoing request carrying a pre-encoded OVL1 frame.
///
/// The runner writes `frame` to the wire, stores `request_id` →
/// `response_tx`, and fulfils the oneshot when a matching response arrives.
pub struct OutboxRequest {
    /// Request ID that matches `FrameHeader::request_id` (u32).
    pub request_id: u32,
    /// Pre-encoded OVL1 frame (header + body).
    pub frame: Vec<u8>,
    /// Receives the raw body of the response frame.
    ///
    /// `Some(bytes)` — the response body arrived successfully.
    /// `None` — the pending entry was evicted (capacity limit or TTL
    /// expiry) before a response was received; the caller
    /// should treat this as a request failure.
    pub response_tx: oneshot::Sender<Option<Vec<u8>>>,
}

/// Default capacity for the per-session RPC outbox channel.
pub const DEFAULT_OUTBOX_DEPTH: usize = 256;

/// Shared request outbox, keyed by `peer_id`.
///
/// `NetworkPeerQuerier` holds an `Arc<SessionOutbox>`. Each `SessionRunner`
/// calls `register` at startup to obtain its receiver, and `unregister`
/// on teardown.
///
/// The internal channel is bounded to `capacity` entries (default
/// [`DEFAULT_OUTBOX_DEPTH`]). `send_request` returns `None` when the
/// channel is full, so the caller sees a "no session" error rather than
/// unbounded memory growth.
pub struct SessionOutbox {
    senders: Mutex<HashMap<[u8; 32], mpsc::Sender<OutboxRequest>>>,
    capacity: usize,
    /// Cumulative count of `send_request` calls dropped because the channel was full.
    drops_total: Arc<AtomicU64>,
}

impl Default for SessionOutbox {
    fn default() -> Self {
        Self {
            senders: Mutex::new(HashMap::new()),
            capacity: DEFAULT_OUTBOX_DEPTH,
            drops_total: Arc::new(AtomicU64::new(0)),
        }
    }
}

impl SessionOutbox {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Create with a custom per-session channel capacity.
    pub fn with_capacity(capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            senders: Mutex::new(HashMap::new()),
            capacity,
            drops_total: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Create with a custom capacity and a shared drop counter.
    ///
    /// Pass `NodeMetrics::session_outbox_drops_counter` here so that drops
    /// are visible in Prometheus metrics.
    pub fn with_capacity_and_drop_counter(
        capacity: usize,
        drops_total: Arc<AtomicU64>,
    ) -> Arc<Self> {
        Arc::new(Self {
            senders: Mutex::new(HashMap::new()),
            capacity,
            drops_total,
        })
    }

    /// Register a new session and return the outbox receiver for that peer.
    pub fn register(&self, peer_id: impl Into<NodeId>) -> mpsc::Receiver<OutboxRequest> {
        // H9 ergonomic accept: see `send_request` для rationale.
        let peer_id: NodeId = peer_id.into();
        let (tx, rx) = mpsc::channel(self.capacity);
        lock!(self.senders).insert(*peer_id.as_bytes(), tx);
        rx
    }

    /// Remove the sender for `peer_id` (called when the session closes).
    pub fn unregister(&self, peer_id: impl Into<NodeId>) {
        // H9 ergonomic accept: see `send_request` для rationale.
        let peer_id: NodeId = peer_id.into();
        lock!(self.senders).remove(peer_id.as_bytes());
    }

    /// Number of currently-registered peer outboxes. Metrics-only.
    pub fn len(&self) -> usize {
        lock!(self.senders).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Send a request to `peer_id` and return a receiver for the response.
    ///
    /// Returns `None` if there is no active session for the peer or the outbox
    /// channel is full (`outbox_depth` requests already queued).
    /// The receiver yields `Some(bytes)` on success or `None` when the
    /// pending entry is evicted before a response arrives.
    pub fn send_request(
        &self,
        peer_id: impl Into<NodeId>,
        request_id: u32,
        frame: Vec<u8>,
    ) -> Option<oneshot::Receiver<Option<Vec<u8>>>> {
        // H9 ergonomic accept: take `impl Into<NodeId>` so callers с
        // raw `[u8; 32]` (session/runtime hot path) и future `NodeId`
        // callers both work без explicit conversion.
        let peer_id: NodeId = peer_id.into();
        let (response_tx, response_rx) = oneshot::channel();
        let req = OutboxRequest {
            request_id,
            frame,
            response_tx,
        };
        let guard = lock!(self.senders);
        let tx = guard.get(peer_id.as_bytes())?;
        if tx.try_send(req).is_err() {
            self.drops_total.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        Some(response_rx)
    }

    ///fire-and-forget frame to `peer_id`.
    ///
    /// Used by gossip-style messages (currently `AnnounceTransport`) where
    /// the sender doesn't expect a reply. Returns `true` on enqueue
    /// `false` if there's no live session or the outbox is full.
    ///
    /// Internally we still go through the per-peer mpsc — we just drop
    /// the response side of the oneshot immediately. The `request_id`
    /// is `0` which the SessionRunner pending-response map will never
    /// match, so the entry naturally TTL-evicts.
    pub fn send_oneway(&self, peer_id: impl Into<NodeId>, frame: Vec<u8>) -> bool {
        // H9 ergonomic accept: see `send_request` для rationale.
        let peer_id: NodeId = peer_id.into();
        let (response_tx, _response_rx) = oneshot::channel();
        let req = OutboxRequest {
            request_id: 0,
            frame,
            response_tx,
        };
        let guard = lock!(self.senders);
        let Some(tx) = guard.get(peer_id.as_bytes()) else {
            return false;
        };
        if tx.try_send(req).is_err() {
            self.drops_total.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        true
    }

    /// Node-ids of all currently registered sessions.
    pub fn peer_ids(&self) -> Vec<[u8; 32]> {
        lock!(self.senders).keys().copied().collect()
    }
}

// ── FrameRouter trait impl ───────────────────────────────────────────────────
//
// Phase 2 session 2 (veilcore extraction): impl block moved here
// от `veilcore::node::dht_glue.rs` так veilcore не violates Rust's
// orphan rule once session moved к а sibling crate (`FrameRouter` is
// veil-dht's trait и `SessionOutbox` is now veil-session's struct
// — neither is local к veilcore).

impl veil_dht::FrameRouter for SessionOutbox {
    fn send_request(
        &self,
        peer: [u8; 32],
        request_id: u32,
        frame: Vec<u8>,
    ) -> Option<tokio::sync::oneshot::Receiver<Option<Vec<u8>>>> {
        SessionOutbox::send_request(self, peer, request_id, frame)
    }
    fn peer_ids(&self) -> Vec<[u8; 32]> {
        SessionOutbox::peer_ids(self)
    }
}
