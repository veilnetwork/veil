//! Hot-standby handoff registry).
//!
//! When a `SessionRunner` initiates a transport handover it sends
//! `SessionMsg::HandoffInit { nonce }` over its primary session and
//! records a [`PendingHandoff`] here keyed by `session_id`. The remote
//! peer, on receiving `HandoffInit`, does the same on its own side and
//! sends `HandoffAck` back. Once both sides see the matching nonce
//! either one may open a fresh transport socket and begin the warm-socket
//! handoff handshake by sending a bare `HandoffAttach { session_id }`.
//!
//! audit cycle-6 (T1): the accept-side ([`peek_and_dispatch`]) then runs a
//! per-socket CHALLENGE-RESPONSE before binding — it `peek`s (does NOT consume)
//! the pending entry, sends a fresh `HandoffChallenge { challenge }`, reads the
//! initiator's `HandoffResponse { hmac = BLAKE3::keyed(tx_key)(session_id ||
//! challenge) }`, recomputes with `rx_key`, and ONLY on a constant-time match
//! `consume`s the one-shot entry and pushes the socket into the runner's
//! `swap_rx`. A failed/forged/replayed response leaves the pending entry intact
//! and closes the socket as a protocol violation. The per-socket challenge is
//! what closes the old replay race (a captured attach+response replayed on a
//! fresh socket gets a different challenge and cannot be answered without the
//! session's `tx_key`).
//!
//! Entries expire [`HandoffRegistry::DEFAULT_TTL`]. The registry
//! is bounded ([`HandoffRegistry::MAX_ENTRIES`]) so an attacker who
//! convinces one side to fire repeated `HandoffInit`s cannot starve
//! memory — when full the oldest entry is evicted to make room.

use std::{
    collections::{BTreeMap, HashMap},
    sync::Mutex,
    time::{Duration, Instant},
};

use veil_cfg::NodeId;

/// A handoff pending on either side of a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingHandoff {
    /// Remote peer's node_id, captured at registration. Diagnostic only — the
    /// accept path keys on `session_id`; ownership is proven by the
    /// challenge-response HMAC (below), not by this field.
    pub peer_node_id: NodeId,
    /// Nonce from `HandoffInit`/`HandoffAck` (primary-session matching of the
    /// init↔ack pair). audit cycle-6 (T1): this nonce is NO LONGER the
    /// warm-socket HMAC input — that is now the receiver's fresh per-socket
    /// `HandoffChallenge`. Random 32 bytes from `OsRng`.
    pub nonce: [u8; 32],
    /// Sender's AEAD TX key for this session (== receiver's RX key under OVL1
    /// DH). The accept-side recomputes the `HandoffResponse` HMAC with this key
    /// over `(session_id || challenge)` to prove the warm socket belongs to a
    /// legitimate session owner. Dropped when the pending entry is evicted.
    pub rx_key: [u8; 32],
    /// Wall-clock point after which this entry is garbage.
    pub expires_at: Instant,
}

/// Thread-safe map of `session_id → PendingHandoff`.
///
/// Protected by a single `Mutex` — every operation is a handful of
/// map ops; contention is negligible and borrowing correctly
/// across async boundaries matters more than granularity.
pub struct HandoffRegistry {
    /// Hard cap on simultaneous pending handoffs. Each pending entry
    /// is ~100 bytes, so 1024 entries = 100 KiB — plenty for any
    /// realistic node and small enough to bound adversarial growth.
    pub const_max_entries: usize,
    /// Lifetime of a pending entry. Short enough that a missed
    /// handoff clears quickly; long enough to tolerate a few seconds
    /// of transport latency on the warm probe.
    ttl: Duration,
    inner: Mutex<Inner>,
}

pub struct Inner {
    by_session: HashMap<[u8; 32], PendingHandoff>,
    /// Secondary index keyed by expiration instant for O(log n) TTL
    /// pruning. Composite key `(expires_at, session_id)` avoids
    /// Instant collisions on coarse clocks.
    by_deadline: BTreeMap<(Instant, [u8; 32]), ()>,
}

impl HandoffRegistry {
    pub const DEFAULT_TTL: Duration = Duration::from_secs(10);
    pub const MAX_ENTRIES: usize = 1024;

    pub fn new() -> Self {
        Self::with_config(Self::DEFAULT_TTL, Self::MAX_ENTRIES)
    }

    pub fn with_config(ttl: Duration, max_entries: usize) -> Self {
        Self {
            const_max_entries: max_entries,
            ttl,
            inner: Mutex::new(Inner {
                by_session: HashMap::new(),
                by_deadline: BTreeMap::new(),
            }),
        }
    }

    /// Register a pending handoff for `session_id`. Replaces any
    /// prior entry for the same session — a session is free to abort
    /// an in-flight handoff and issue a new one with a fresh nonce.
    ///
    /// Callers supply the `peer_node_id` and `rx_key` extracted from
    /// the live session state; the registry stores them verbatim.
    pub fn insert(
        &self,
        session_id: [u8; 32],
        peer_node_id: NodeId,
        nonce: [u8; 32],
        rx_key: [u8; 32],
    ) {
        let now = Instant::now();
        let expires_at = now + self.ttl;
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());

        // Prune expired entries opportunistically so the map doesn't
        // grow indefinitely on a quiet session that never evicts.
        Self::prune_locked(&mut inner, now);

        // Cap enforcement — if still full, evict the oldest.
        if inner.by_session.len() >= self.const_max_entries
            && !inner.by_session.contains_key(&session_id)
            && let Some((&(oldest_t, oldest_sid), ())) = inner.by_deadline.iter().next()
        {
            inner.by_deadline.remove(&(oldest_t, oldest_sid));
            inner.by_session.remove(&oldest_sid);
        }

        // If an entry for this session already exists, remove its
        // deadline-index row before overwriting. Copy the deadline
        // out so we can call the `&mut` method without tripping the
        // borrow checker on the shared `inner` reference.
        let old_deadline = inner.by_session.get(&session_id).map(|e| e.expires_at);
        if let Some(t) = old_deadline {
            inner.by_deadline.remove(&(t, session_id));
        }
        let entry = PendingHandoff {
            peer_node_id,
            nonce,
            rx_key,
            expires_at,
        };
        inner.by_deadline.insert((expires_at, session_id), ());
        inner.by_session.insert(session_id, entry);
    }

    /// Look up a pending entry without consuming it. Originally designed
    /// for the accept-side to verify HMAC before commit; production
    /// path now folds peek+consume in a single atomic `consume` call
    /// (which prunes expired entries internally too). Retained for
    /// tests + future "verify-then-commit" workflows.
    ///
    /// Phase 2 session 2: `#[cfg(test)]` removed so cross-crate tests
    /// in veilcore (Strategy A) can reach this method.
    pub fn peek(&self, session_id: &[u8; 32]) -> Option<PendingHandoff> {
        let now = Instant::now();
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        // Prune on read so expired entries are invisible.
        Self::prune_locked(&mut inner, now);
        inner.by_session.get(session_id).cloned()
    }

    /// Atomically look up + remove an entry. The accept-side code
    /// uses this after a successful HMAC match so the handoff token
    /// is one-shot: a second socket presenting the same `HandoffAttach`
    /// sees no match.
    pub fn consume(&self, session_id: &[u8; 32]) -> Option<PendingHandoff> {
        let now = Instant::now();
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        Self::prune_locked(&mut inner, now);
        let entry = inner.by_session.remove(session_id)?;
        inner.by_deadline.remove(&(entry.expires_at, *session_id));
        Some(entry)
    }

    /// Drop all entries whose `expires_at ≤ now`. Called
    /// opportunistically from `insert`/`peek`/`consume`, and by a periodic
    /// background tick (`spawn_handoff_prune_task`) so quiet sessions
    /// don't accumulate stale entries between operations.
    pub fn prune_expired(&self) {
        let now = Instant::now();
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        Self::prune_locked(&mut inner, now);
    }

    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .by_session
            .len()
    }

    /// `true` if nothing is currently buffered.  Companion to [`Self::len`].
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn prune_locked(inner: &mut Inner, now: Instant) {
        // BTreeMap is ordered ascending by key, so the first entries
        // are the oldest deadlines. Pop until we see one that hasn't
        // expired — O(k log n) for k expired entries.
        while let Some((&(t, sid), ())) = inner.by_deadline.iter().next() {
            if t > now {
                break;
            }
            inner.by_deadline.remove(&(t, sid));
            inner.by_session.remove(&sid);
        }
    }
}

impl Default for HandoffRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for HandoffRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandoffRegistry")
            .field("ttl", &self.ttl)
            .field("max_entries", &self.const_max_entries)
            .field("len", &self.len())
            .finish()
    }
}

// ── SessionSwapRegistry ───────────────────────────────────────────────────────
//
// Second registry colocated with `HandoffRegistry`: a per-runtime map of
// `session_id → Sender<BoxIoStream>` that lets the accept-side branch
// deliver an incoming warm socket to the exact `SessionRunner`
// whose `swap_rx` was constructed at session start.
//
// Kept separate from `HandoffRegistry` because its lifetime is different:
// `HandoffRegistry` entries expire on TTL (seconds), but a session's
// swap_tx lives for the full duration of the session — registered when
// the runner is constructed, unregistered when it drops.

use tokio::sync::mpsc;
use veil_transport::BoxIoStream;

/// Per-session handoff handles: the channel sender that delivers a
/// warm-socket to the runner PLUS the session's AEAD TX key (needed
/// by the initiator side for computing the `HandoffAttach` HMAC).
#[derive(Clone)]
pub struct SessionHandoffHandles {
    pub swap_tx: mpsc::Sender<BoxIoStream>,
    /// Session's TX AEAD key (== peer's RX key under OVL1 DH). Used to
    /// seal `HandoffAttach` on the initiator side; on the receiver side
    /// `PendingHandoff.rx_key` covers the verification path, so this
    /// field is not consulted on accept.
    pub tx_key: [u8; 32],
}

/// Per-runtime registry of session-id → handoff handles. A
/// [`super::super::session::runner::SessionRunner`] inserts its
/// `swap_tx` + tx_key here at construction and a `SwapRegistryGuard`
/// removes the entry on drop so stale senders can't accumulate across
/// reloads or session closes.
pub struct SessionSwapRegistry {
    inner: Mutex<SwapRegistryInner>,
}

pub struct SwapRegistryInner {
    by_session: HashMap<[u8; 32], SessionHandoffHandles>,
    /// Secondary index: `peer_node_id → session_id`. Let admin commands
    /// address a session by peer (what operators know) without needing
    /// to pivot through `SessionRegistry`. Critical because
    /// `SessionRegistry` may hold a **different** session_id when both
    /// sides raced outbound-vs-inbound and dedup chose a different
    /// winner than what this runtime's live runner actually uses — the
    /// swap registry always reflects the RUNNING session.
    by_peer: HashMap<NodeId, [u8; 32]>,
}

impl SessionSwapRegistry {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(SwapRegistryInner {
                by_session: HashMap::new(),
                by_peer: HashMap::new(),
            }),
        }
    }

    /// Register a session's handoff handles. Returns a guard whose
    /// Drop removes the entry — callers should bind the guard to the
    /// SessionRunner's lifetime so it unregisters automatically.
    ///
    /// Re-insert with the same `session_id` silently replaces the
    /// previous entry (the old `Sender` is dropped, closing its
    /// channel from the receiver's perspective).
    ///
    /// `peer_node_id` populates the secondary peer-index used by
    /// admin commands. Collisions (two sessions to the same peer —
    /// shouldn't happen post-dedup but can briefly during handshake
    /// races) resolve last-write-wins on `by_peer`; `by_session` is
    /// still authoritative.
    pub fn register(
        self: &std::sync::Arc<Self>,
        session_id: [u8; 32],
        peer_node_id: NodeId,
        tx: mpsc::Sender<BoxIoStream>,
        tx_key: [u8; 32],
    ) -> SwapRegistryGuard {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        inner.by_session.insert(
            session_id,
            SessionHandoffHandles {
                swap_tx: tx,
                tx_key,
            },
        );
        inner.by_peer.insert(peer_node_id, session_id);
        SwapRegistryGuard {
            registry: std::sync::Arc::clone(self),
            session_id,
            peer_node_id,
        }
    }

    /// Look up a session's swap sender for delivery of a warm socket.
    /// Returns a clone so the caller can `send(..)` without holding
    /// the registry lock across an `.await`.
    pub fn get(&self, session_id: &[u8; 32]) -> Option<mpsc::Sender<BoxIoStream>> {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .by_session
            .get(session_id)
            .map(|h| h.swap_tx.clone())
    }

    /// Look up the session's TX AEAD key without claiming the swap
    /// channel. Used by the admin-driven warm-probe (B5) to seal
    /// `HandoffAttach` with the right key material.
    pub fn tx_key(&self, session_id: &[u8; 32]) -> Option<[u8; 32]> {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .by_session
            .get(session_id)
            .map(|h| h.tx_key)
    }

    /// Resolve `peer_node_id → session_id` for admin commands that
    /// address a session by peer.
    pub fn session_id_for_peer(&self, peer_node_id: &NodeId) -> Option<[u8; 32]> {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .by_peer
            .get(peer_node_id)
            .copied()
    }

    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .by_session
            .len()
    }

    /// `true` if nothing is currently registered.  Companion to [`Self::len`].
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn remove(&self, session_id: &[u8; 32], peer_node_id: &NodeId) {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        inner.by_session.remove(session_id);
        // Only clear `by_peer` if the entry still points at THIS session
        // — a concurrent re-register with a different session_id would
        // have overwritten the peer row and should survive our drop.
        if inner.by_peer.get(peer_node_id) == Some(session_id) {
            inner.by_peer.remove(peer_node_id);
        }
    }
}

impl Default for SessionSwapRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for SessionSwapRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionSwapRegistry")
            .field("len", &self.len())
            .finish()
    }
}

/// RAII guard: drops the matching entry [`SessionSwapRegistry`]
/// when the runner exits, so accept-side lookups on a dead session
/// fail fast instead of handing a socket to a no-longer-listening
/// channel.
pub struct SwapRegistryGuard {
    registry: std::sync::Arc<SessionSwapRegistry>,
    session_id: [u8; 32],
    peer_node_id: NodeId,
}

impl Drop for SwapRegistryGuard {
    fn drop(&mut self) {
        self.registry.remove(&self.session_id, &self.peer_node_id);
    }
}

// ── PrefixedStream ────────────────────────────────────────────────────────────
//
// An `AsyncRead + AsyncWrite` wrapper that returns a pre-captured `prefix`
// of bytes before forwarding reads to the underlying stream. Used by the
// accept-side peek logic: we read the first 16 bytes to inspect
// the OVL1 frame header, and if the frame is NOT `HandoffAttach` we wrap
// the socket in this type so the OVL1 handshake sees the peeked bytes as
// the start of its normal input.

use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Wraps an inner `AsyncRead+AsyncWrite` stream + a `Vec<u8>` prefix.
/// The first `prefix.len` bytes come from the prefix; after that reads
/// proxy to `inner`. Writes always proxy straight to `inner`.
pub struct PrefixedStream<S> {
    prefix: Vec<u8>,
    prefix_pos: usize,
    inner: S,
}

impl<S> PrefixedStream<S> {
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix,
            prefix_pos: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // Drain prefix first.
        if self.prefix_pos < self.prefix.len() {
            let remaining = &self.prefix[self.prefix_pos..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            self.prefix_pos += n;
            return Poll::Ready(Ok(()));
        }
        // Prefix exhausted — forward to inner.
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// `PrefixedStream<S>` picks up `IoStream` via the workspace's blanket impl
// (see `transport::traits`) for any `AsyncRead + AsyncWrite + Send + Sync +
// Unpin` type — no explicit impl needed here.

// ── HandoffAckWaiters ─────────────────────────────────────────────────────────
//
// Third registry next to `HandoffRegistry` + `SessionSwapRegistry`: maps a
// session to the initiator task (warm-probe, stage (b)) that is waiting for
// `HandoffAck` to arrive over the primary.
//
// When a SessionRunner dispatches an incoming `HandoffAck` it looks up the
// ack's owning session here and forwards the nonce. The previous design
// used a per-runner field (`handoff_ack_tx`) set at runner-construction
// time — which was wrong, because the warm-probe task is spawned AFTER the
// session runner exists. A shared map keyed by `session_id` lets the probe
// register whenever it's ready and tear down on drop via a guard.

/// Per-runtime registry of session-id → HandoffAck receiver's sender half.
/// One entry per in-flight handoff. Re-insert on the same session_id
/// silently replaces the previous sender (the old channel closes).
pub struct HandoffAckWaiters {
    inner: Mutex<HashMap<[u8; 32], mpsc::Sender<[u8; 32]>>>,
}

impl HandoffAckWaiters {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Register a waiter. Returns an RAII guard that removes the entry
    /// on drop — the initiator task should bind the guard to its own
    /// lifetime so a crashed/cancelled probe doesn't leak senders.
    pub fn register(
        self: &std::sync::Arc<Self>,
        session_id: [u8; 32],
        tx: mpsc::Sender<[u8; 32]>,
    ) -> HandoffAckWaiterGuard {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(session_id, tx);
        HandoffAckWaiterGuard {
            registry: std::sync::Arc::clone(self),
            session_id,
        }
    }

    /// Look up the waiter's sender for delivery of a nonce. Returns a
    /// clone so the caller can drive the send outside of the registry
    /// lock.
    pub fn get(&self, session_id: &[u8; 32]) -> Option<mpsc::Sender<[u8; 32]>> {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(session_id)
            .cloned()
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    /// `true` if no waiter is currently registered.  Companion to [`Self::len`].
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn remove(&self, session_id: &[u8; 32]) {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(session_id);
    }
}

impl Default for HandoffAckWaiters {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for HandoffAckWaiters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandoffAckWaiters")
            .field("len", &self.len())
            .finish()
    }
}

pub struct HandoffAckWaiterGuard {
    registry: std::sync::Arc<HandoffAckWaiters>,
    session_id: [u8; 32],
}

impl Drop for HandoffAckWaiterGuard {
    fn drop(&mut self) {
        self.registry.remove(&self.session_id);
    }
}

// ── Accept-side dispatch ──────────────────────────────────────────────────────
//
// [`peek_and_dispatch`] is the one-stop entry point the accept-side of every
// listener (TCP, TLS, WSS, QUIC) calls BEFORE kicking off an OVL1 handshake.
//
// It reads the first 16 bytes to inspect the OVL1 frame header. Two
// outcomes:
//
// * `PeekOutcome::HandoffBound` — the frame was `SessionMsg::HandoffAttach`
// and the payload's `session_id` + HMAC matched a pending entry in
// `HandoffRegistry`, AND the same `session_id` had a live swap_tx
// registered in `SessionSwapRegistry`. The socket (prefix-replayed so
// no bytes are lost) has been sent into that runner's `swap_rx`.
// Caller stops: the old OVL1 handshake path is NOT run.
//
// * `PeekOutcome::Handshake(stream)` — the frame was anything else (or the
// handoff verification failed). The returned stream is a
// [`PrefixedStream`] that replays the peeked 16 bytes, so the OVL1
// handshake sees them as the start of its normal input.
//
// The HMAC check uses the `rx_key` stored in the `PendingHandoff` entry by
// the receiver side's `HandoffInit` handler. Computed as
// `BLAKE3::keyed(rx_key)(session_id || nonce)` — matches the initiator's
// `compute_hmac` call on the sender side under OVL1 DH.

pub enum PeekOutcome {
    /// Socket was bound to an existing session via hot-standby handoff.
    /// No further work for the accept-side.
    HandoffBound,
    /// Not a handoff — caller should proceed with OVL1 handshake using
    /// the returned stream (which replays the peeked 16 bytes).
    Handshake(Box<dyn veil_transport::IoStream>),
    /// Stream was closed / timed out / malformed header — caller should
    /// drop the socket.
    Drop(String),
}

/// stage (d) Task 4b entry point.
///
/// Timeout budget is small (`handshake_peek_timeout_secs`) because a
/// legitimate handoff sends the `HandoffAttach` frame immediately on
/// connection; a silent peek-read is a sign the socket is junk traffic
/// or a scan probe.
pub async fn peek_and_dispatch<S>(
    stream: S,
    handoff_registry: &HandoffRegistry,
    swap_registry: &SessionSwapRegistry,
    peek_timeout_secs: u64,
) -> PeekOutcome
where
    S: veil_transport::IoStream + 'static,
{
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use veil_proto::{
        codec::{decode_header, encode_header},
        family::{FrameFamily, SessionMsg},
        header::FrameHeader,
        session::{HandoffAttachPayload, HandoffChallengePayload, HandoffResponsePayload},
    };

    const HEADER_SIZE: usize = veil_proto::header::HEADER_SIZE;

    let mut stream: Box<dyn veil_transport::IoStream> = Box::new(stream);

    // Peek the 16-byte header.
    let mut hdr_buf = [0u8; HEADER_SIZE];
    match tokio::time::timeout(
        std::time::Duration::from_secs(peek_timeout_secs),
        stream.read_exact(&mut hdr_buf),
    )
    .await
    {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => return PeekOutcome::Drop(format!("peek read error: {e}")),
        Err(_) => return PeekOutcome::Drop(format!("peek timed out after {peek_timeout_secs}s")),
    }

    // Cheap filter: not a session frame → immediately hand to handshake.
    let hdr = match decode_header(&hdr_buf) {
        Ok(h) => h,
        // Not decodable as header — malformed, but don't drop here:
        // handshake may accept arbitrary leading bytes on some legacy paths.
        Err(_) => {
            return PeekOutcome::Handshake(Box::new(PrefixedStream::new(hdr_buf.to_vec(), stream)));
        }
    };
    if hdr.family != FrameFamily::Session as u8 || hdr.msg_type != SessionMsg::HandoffAttach as u16
    {
        return PeekOutcome::Handshake(Box::new(PrefixedStream::new(hdr_buf.to_vec(), stream)));
    }

    // It's a HandoffAttach (a bare announce — audit cycle-6 T1). Read the body.
    if hdr.body_len as usize != HandoffAttachPayload::WIRE_SIZE {
        return PeekOutcome::Drop(format!(
            "HandoffAttach body_len={} expected {}",
            hdr.body_len,
            HandoffAttachPayload::WIRE_SIZE,
        ));
    }
    let mut body = vec![0u8; hdr.body_len as usize];
    match tokio::time::timeout(
        std::time::Duration::from_secs(peek_timeout_secs),
        stream.read_exact(&mut body),
    )
    .await
    {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => return PeekOutcome::Drop(format!("HandoffAttach body read error: {e}")),
        Err(_) => return PeekOutcome::Drop("HandoffAttach body timeout".to_owned()),
    }
    let attach = match HandoffAttachPayload::decode(&body) {
        Ok(p) => p,
        Err(e) => return PeekOutcome::Drop(format!("bad HandoffAttach: {e}")),
    };

    // audit cycle-6 (T1): challenge-response. Look up the pending entry WITHOUT
    // consuming it (`peek`) so an attacker's replayed attach cannot burn the
    // legitimate initiator's one-shot token before it answers a challenge.
    let pending = match handoff_registry.peek(&attach.session_id) {
        Some(p) => p,
        None => {
            return PeekOutcome::Drop(
                "HandoffAttach: no pending handoff for session_id".to_owned(),
            );
        }
    };

    // Send a FRESH per-socket challenge. Replay on a different socket gets a
    // different challenge, so a copied response is useless; forging a response
    // requires the session's `tx_key`, which the attacker does not have.
    let challenge: [u8; 32] = {
        use rand_core::{OsRng, RngCore};
        let mut c = [0u8; 32];
        OsRng.fill_bytes(&mut c);
        c
    };
    let chal_body = HandoffChallengePayload { challenge }.encode();
    let mut chal_hdr = FrameHeader::new(
        FrameFamily::Session as u8,
        SessionMsg::HandoffChallenge as u16,
    );
    chal_hdr.body_len = chal_body.len() as u32;
    let mut chal_frame = encode_header(&chal_hdr).to_vec();
    chal_frame.extend_from_slice(&chal_body);
    match tokio::time::timeout(
        std::time::Duration::from_secs(peek_timeout_secs),
        stream.write_all(&chal_frame),
    )
    .await
    {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => return PeekOutcome::Drop(format!("HandoffChallenge write error: {e}")),
        Err(_) => return PeekOutcome::Drop("HandoffChallenge write timeout".to_owned()),
    }

    // Read the initiator's HandoffResponse (header + body).
    let mut resp_hdr_buf = [0u8; HEADER_SIZE];
    match tokio::time::timeout(
        std::time::Duration::from_secs(peek_timeout_secs),
        stream.read_exact(&mut resp_hdr_buf),
    )
    .await
    {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => return PeekOutcome::Drop(format!("HandoffResponse header read error: {e}")),
        Err(_) => return PeekOutcome::Drop("HandoffResponse header timeout".to_owned()),
    }
    let resp_hdr = match decode_header(&resp_hdr_buf) {
        Ok(h) => h,
        Err(e) => return PeekOutcome::Drop(format!("bad HandoffResponse header: {e}")),
    };
    if resp_hdr.family != FrameFamily::Session as u8
        || resp_hdr.msg_type != SessionMsg::HandoffResponse as u16
        || resp_hdr.body_len as usize != HandoffResponsePayload::WIRE_SIZE
    {
        return PeekOutcome::Drop("HandoffResponse: wrong frame type/size".to_owned());
    }
    let mut resp_body = vec![0u8; resp_hdr.body_len as usize];
    match tokio::time::timeout(
        std::time::Duration::from_secs(peek_timeout_secs),
        stream.read_exact(&mut resp_body),
    )
    .await
    {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => return PeekOutcome::Drop(format!("HandoffResponse body read error: {e}")),
        Err(_) => return PeekOutcome::Drop("HandoffResponse body timeout".to_owned()),
    }
    let response = match HandoffResponsePayload::decode(&resp_body) {
        Ok(p) => p,
        Err(e) => return PeekOutcome::Drop(format!("bad HandoffResponse: {e}")),
    };

    // Verify the response HMAC over (session_id || challenge) with the pending
    // entry's `rx_key`. Constant-time compare to avoid leaking mismatch
    // position. NOTE: the entry is still in the registry — only consume it on
    // success, so a wrong/forged response leaves the legit token intact.
    let expected =
        HandoffAttachPayload::compute_hmac(&pending.rx_key, &attach.session_id, &challenge);
    use subtle::ConstantTimeEq as _;
    if expected.ct_eq(&response.hmac).unwrap_u8() == 0 {
        return PeekOutcome::Drop("HandoffResponse: HMAC mismatch".to_owned());
    }

    // Proof verified — now atomically consume the one-shot token. A concurrent
    // socket that already consumed it (legit double-fire / lost race) yields
    // None here, in which case this socket loses cleanly.
    if handoff_registry.consume(&attach.session_id).is_none() {
        return PeekOutcome::Drop(
            "HandoffAttach: pending handoff already consumed (raced)".to_owned(),
        );
    }

    // Look up the live runner's swap channel. A session whose runner has
    // already dropped would have removed itself from `swap_registry` via
    // `SwapRegistryGuard::drop` — a None here means the runner's gone.
    let swap_tx = match swap_registry.get(&attach.session_id) {
        Some(t) => t,
        None => {
            return PeekOutcome::Drop(
                "HandoffAttach: matching session has no live swap channel".to_owned(),
            );
        }
    };

    // Hand the bare stream over. NOTE: we've already consumed the
    // HandoffAttach header+body, so the runner's `self.stream = new_stream`
    // path inherits a "clean" byte stream positioned at the next frame.
    if swap_tx.send(stream).await.is_err() {
        return PeekOutcome::Drop(
            "HandoffAttach: swap_rx receiver dropped between lookup and send".to_owned(),
        );
    }
    PeekOutcome::HandoffBound
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sid(byte: u8) -> [u8; 32] {
        [byte; 32]
    }
    fn nid(byte: u8) -> NodeId {
        NodeId::from([byte; 32])
    }
    fn nonce(byte: u8) -> [u8; 32] {
        [byte; 32]
    }
    fn key(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn insert_then_consume_returns_entry() {
        let r = HandoffRegistry::new();
        r.insert(sid(1), nid(9), nonce(0xAA), key(0xBB));
        let got = r.consume(&sid(1)).expect("entry must be present");
        assert_eq!(got.peer_node_id, nid(9));
        assert_eq!(got.nonce, nonce(0xAA));
        assert_eq!(got.rx_key, key(0xBB));
        // Consume is one-shot.
        assert!(
            r.consume(&sid(1)).is_none(),
            "second consume on the same session_id must see no entry"
        );
    }

    #[test]
    fn peek_does_not_remove() {
        let r = HandoffRegistry::new();
        r.insert(sid(1), nid(9), nonce(0xAA), key(0xBB));
        assert!(r.peek(&sid(1)).is_some());
        assert!(r.peek(&sid(1)).is_some(), "peek must be idempotent");
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn expired_entries_are_pruned_on_access() {
        let r = HandoffRegistry::with_config(Duration::from_millis(5), 64);
        r.insert(sid(1), nid(9), nonce(0xAA), key(0xBB));
        assert_eq!(r.len(), 1);
        std::thread::sleep(Duration::from_millis(15));
        // Prune happens as a side effect of any subsequent op.
        assert!(
            r.peek(&sid(1)).is_none(),
            "expired entry should be invisible after TTL"
        );
        assert_eq!(r.len(), 0);
    }

    #[test]
    fn prune_expired_is_noop_on_fresh_entries() {
        let r = HandoffRegistry::new();
        r.insert(sid(1), nid(9), nonce(0xAA), key(0xBB));
        r.insert(sid(2), nid(8), nonce(0xCC), key(0xDD));
        r.prune_expired();
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn reinserting_same_session_replaces_previous_entry() {
        // A session may reissue a handoff with a new nonce — the old
        // entry must be cleanly replaced, not leaked as a second row
        // in the deadline index.
        let r = HandoffRegistry::new();
        r.insert(sid(1), nid(9), nonce(0xAA), key(0xBB));
        r.insert(sid(1), nid(9), nonce(0x11), key(0xBB));
        assert_eq!(r.len(), 1);
        let got = r.consume(&sid(1)).unwrap();
        assert_eq!(got.nonce, nonce(0x11), "latest insert must win");
    }

    // ── SessionSwapRegistry tests ───────────────────────────────────────

    #[test]
    fn swap_registry_registers_and_looks_up() {
        let r = std::sync::Arc::new(SessionSwapRegistry::new());
        let (tx, mut rx) = tokio::sync::mpsc::channel::<BoxIoStream>(1);
        let _guard = r.register(sid(1), NodeId::from([0x11u8; 32]), tx, [0u8; 32]);
        assert!(r.get(&sid(1)).is_some());
        assert_eq!(r.len(), 1);
        // get returns a clone, original receiver is still wired up.
        let _ = r.get(&sid(1)).unwrap();
        // Receiver has not seen anything (nobody sent).
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn swap_registry_guard_auto_unregisters_on_drop() {
        let r = std::sync::Arc::new(SessionSwapRegistry::new());
        let (tx, _rx) = tokio::sync::mpsc::channel::<BoxIoStream>(1);
        {
            let _guard = r.register(sid(2), NodeId::from([0x22u8; 32]), tx, [0u8; 32]);
            assert_eq!(r.len(), 1);
        } // guard dropped here
        assert_eq!(r.len(), 0, "SwapRegistryGuard::drop must remove the entry");
        assert!(r.get(&sid(2)).is_none());
    }

    #[test]
    fn swap_registry_reregister_replaces_previous_sender() {
        let r = std::sync::Arc::new(SessionSwapRegistry::new());
        let (tx1, mut rx1) = tokio::sync::mpsc::channel::<BoxIoStream>(1);
        let _g1 = r.register(sid(3), NodeId::from([0x33u8; 32]), tx1, [0u8; 32]);
        let (tx2, _rx2) = tokio::sync::mpsc::channel::<BoxIoStream>(1);
        let _g2 = r.register(sid(3), NodeId::from([0x33u8; 32]), tx2, [0u8; 32]);
        // The original sender's channel should now be closed because
        // the only live Sender was the one we replaced.
        assert!(
            rx1.try_recv().is_err(),
            "old receiver should see empty/closed after replacement"
        );
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn cap_enforces_oldest_eviction_under_pressure() {
        // With MAX_ENTRIES = 3, the 4th distinct insert must evict the
        // oldest entry — not reject the new one, not silently collide.
        let r = HandoffRegistry::with_config(Duration::from_secs(60), 3);
        for i in 1..=4u8 {
            r.insert(sid(i), nid(i), nonce(i), key(i));
            // Tiny sleep to ensure distinct Instants for deterministic ordering.
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(r.len(), 3);
        assert!(
            r.peek(&sid(1)).is_none(),
            "oldest entry (session 1) should have been evicted"
        );
        assert!(
            r.peek(&sid(4)).is_some(),
            "newest entry (session 4) must still be present"
        );
    }

    // ── PrefixedStream tests ────────────────────────────────────────────

    #[tokio::test]
    async fn prefixed_stream_replays_prefix_then_forwards_reads() {
        use tokio::io::AsyncReadExt as _;
        // Inner stream contains bytes 0x10..0x1F, prefix is 0xAA 0xBB 0xCC.
        // Expected read order: 0xAA 0xBB 0xCC 0x10 0x11 0x12...
        let (mut a, b) = tokio::io::duplex(64);
        tokio::io::AsyncWriteExt::write_all(&mut a, &(0x10u8..0x20).collect::<Vec<_>>())
            .await
            .unwrap();
        drop(a); // close, so reader sees EOF after inner bytes

        let prefix = vec![0xAAu8, 0xBB, 0xCC];
        let mut prefixed = PrefixedStream::new(prefix, b);

        let mut got = Vec::new();
        prefixed.read_to_end(&mut got).await.unwrap();
        assert_eq!(got[..3], [0xAA, 0xBB, 0xCC], "prefix must come first");
        assert_eq!(got.len(), 3 + 16);
        assert_eq!(got[3..], (0x10u8..0x20).collect::<Vec<_>>()[..]);
    }

    #[tokio::test]
    async fn prefixed_stream_with_empty_prefix_is_passthrough() {
        use tokio::io::AsyncReadExt as _;
        let (mut a, b) = tokio::io::duplex(64);
        tokio::io::AsyncWriteExt::write_all(&mut a, b"hello")
            .await
            .unwrap();
        drop(a);
        let mut prefixed = PrefixedStream::new(Vec::new(), b);
        let mut s = String::new();
        prefixed.read_to_string(&mut s).await.unwrap();
        assert_eq!(s, "hello");
    }

    // ── peek_and_dispatch tests ─────────────────────────────────────────
    //
    // audit cycle-6 (T1): the warm-socket flow is now a challenge-response:
    //   initiator → HandoffAttach{session_id}
    //   receiver  → HandoffChallenge{fresh}
    //   initiator → HandoffResponse{hmac(key, session_id, challenge)}
    // These test helpers drive the initiator side over a duplex pipe.

    /// Send a bare `HandoffAttach{session_id}` frame on `client`.
    async fn send_attach(client: &mut (impl tokio::io::AsyncWrite + Unpin), session_id: [u8; 32]) {
        use tokio::io::AsyncWriteExt as _;
        use veil_proto::{
            codec::encode_header,
            family::{FrameFamily, SessionMsg},
            header::FrameHeader,
            session::HandoffAttachPayload,
        };
        let body = HandoffAttachPayload { session_id }.encode();
        let mut hdr =
            FrameHeader::new(FrameFamily::Session as u8, SessionMsg::HandoffAttach as u16);
        hdr.body_len = body.len() as u32;
        let mut wire = encode_header(&hdr).to_vec();
        wire.extend_from_slice(&body);
        client.write_all(&wire).await.unwrap();
    }

    /// Read a `HandoffChallenge` frame from `client`, returning the challenge.
    async fn read_challenge(client: &mut (impl tokio::io::AsyncRead + Unpin)) -> [u8; 32] {
        use tokio::io::AsyncReadExt as _;
        use veil_proto::{codec::decode_header, session::HandoffChallengePayload};
        const H: usize = veil_proto::header::HEADER_SIZE;
        let mut hdr_buf = [0u8; H];
        client.read_exact(&mut hdr_buf).await.unwrap();
        let hdr = decode_header(&hdr_buf).unwrap();
        let mut body = vec![0u8; hdr.body_len as usize];
        client.read_exact(&mut body).await.unwrap();
        HandoffChallengePayload::decode(&body).unwrap().challenge
    }

    /// Send a `HandoffResponse{hmac(key, session_id, challenge)}` frame.
    async fn send_response(
        client: &mut (impl tokio::io::AsyncWrite + Unpin),
        key: [u8; 32],
        session_id: [u8; 32],
        challenge: [u8; 32],
    ) {
        use tokio::io::AsyncWriteExt as _;
        use veil_proto::{
            codec::encode_header,
            family::{FrameFamily, SessionMsg},
            header::FrameHeader,
            session::{HandoffAttachPayload, HandoffResponsePayload},
        };
        let hmac = HandoffAttachPayload::compute_hmac(&key, &session_id, &challenge);
        let body = HandoffResponsePayload { hmac }.encode();
        let mut hdr = FrameHeader::new(
            FrameFamily::Session as u8,
            SessionMsg::HandoffResponse as u16,
        );
        hdr.body_len = body.len() as u32;
        let mut wire = encode_header(&hdr).to_vec();
        wire.extend_from_slice(&body);
        client.write_all(&wire).await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn peek_and_dispatch_routes_valid_handoff_attach_to_swap_tx() {
        use tokio::io::AsyncWriteExt as _;

        let handoff = std::sync::Arc::new(HandoffRegistry::new());
        let swap_reg = std::sync::Arc::new(SessionSwapRegistry::new());

        let session_id = [0x42u8; 32];
        let peer_id: NodeId = [0x66u8; 32].into();
        let nonce = [0x77u8; 32];
        let rx_key = [0x88u8; 32];
        handoff.insert(session_id, peer_id, nonce, rx_key);

        let (tx, mut rx) = tokio::sync::mpsc::channel::<BoxIoStream>(1);
        let _guard = swap_reg.register(session_id, [0x99u8; 32].into(), tx, [0u8; 32]);

        let (mut client, server) = tokio::io::duplex(1024);
        // Drive the accept-side and the initiator side concurrently (the
        // challenge round-trip needs both halves live at once).
        let h = std::sync::Arc::clone(&handoff);
        let sr = std::sync::Arc::clone(&swap_reg);
        let accept = tokio::spawn(async move { peek_and_dispatch(server, &h, &sr, 2).await });

        send_attach(&mut client, session_id).await;
        let challenge = read_challenge(&mut client).await;
        // Honest initiator answers with the rx_key (== tx_key under OVL1 DH).
        send_response(&mut client, rx_key, session_id, challenge).await;
        client.write_all(b"POST-ATTACH-BYTES").await.unwrap();

        let outcome = accept.await.unwrap();
        assert!(
            matches!(outcome, PeekOutcome::HandoffBound),
            "valid challenge-response handoff must route to HandoffBound"
        );

        let mut bound_stream = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("swap send timeout")
            .expect("swap_tx dropped");
        use tokio::io::AsyncReadExt as _;
        let mut buf = [0u8; 17];
        bound_stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(
            &buf, b"POST-ATTACH-BYTES",
            "stream must be positioned after the response frame"
        );
    }

    /// audit cycle-6 (T1): the core security property. A passive observer that
    /// CAPTURES a full valid handoff (attach + response) and REPLAYS the exact
    /// bytes on a fresh socket must be rejected — because the receiver issues a
    /// NEW challenge per socket, so the captured response no longer matches.
    #[tokio::test(flavor = "current_thread")]
    async fn peek_and_dispatch_rejects_replayed_response_t1() {
        use veil_proto::session::HandoffAttachPayload;
        let handoff = std::sync::Arc::new(HandoffRegistry::new());
        let swap_reg = std::sync::Arc::new(SessionSwapRegistry::new());
        let session_id = [0x42u8; 32];
        let rx_key = [0x88u8; 32];
        handoff.insert(session_id, [0x66u8; 32].into(), [0x77u8; 32], rx_key);
        let (tx, _rx) = tokio::sync::mpsc::channel::<BoxIoStream>(1);
        let _guard = swap_reg.register(session_id, [0x99u8; 32].into(), tx, [0u8; 32]);

        // ── Session 1: a legitimate handoff, capturing the response HMAC. ──
        let (mut c1, s1) = tokio::io::duplex(1024);
        let h1 = std::sync::Arc::clone(&handoff);
        let sr1 = std::sync::Arc::clone(&swap_reg);
        let accept1 = tokio::spawn(async move { peek_and_dispatch(s1, &h1, &sr1, 2).await });
        send_attach(&mut c1, session_id).await;
        let challenge1 = read_challenge(&mut c1).await;
        let captured_hmac = HandoffAttachPayload::compute_hmac(&rx_key, &session_id, &challenge1);
        {
            use tokio::io::AsyncWriteExt as _;
            use veil_proto::{
                codec::encode_header,
                family::{FrameFamily, SessionMsg},
                header::FrameHeader,
                session::HandoffResponsePayload,
            };
            let body = HandoffResponsePayload {
                hmac: captured_hmac,
            }
            .encode();
            let mut hdr = FrameHeader::new(
                FrameFamily::Session as u8,
                SessionMsg::HandoffResponse as u16,
            );
            hdr.body_len = body.len() as u32;
            let mut wire = encode_header(&hdr).to_vec();
            wire.extend_from_slice(&body);
            c1.write_all(&wire).await.unwrap();
        }
        let _ = accept1.await.unwrap(); // session 1 may bind (consumes entry)

        // ── Session 2 (attacker): re-insert a pending entry to simulate a
        // fresh handoff opportunity, then REPLAY the captured response. The
        // receiver's challenge2 differs, so captured_hmac must NOT verify. ──
        handoff.insert(session_id, [0x66u8; 32].into(), [0x77u8; 32], rx_key);
        let (mut c2, s2) = tokio::io::duplex(1024);
        let h2 = std::sync::Arc::clone(&handoff);
        let sr2 = std::sync::Arc::clone(&swap_reg);
        let accept2 = tokio::spawn(async move { peek_and_dispatch(s2, &h2, &sr2, 2).await });
        send_attach(&mut c2, session_id).await;
        let _challenge2 = read_challenge(&mut c2).await; // different fresh challenge
        {
            use tokio::io::AsyncWriteExt as _;
            use veil_proto::{
                codec::encode_header,
                family::{FrameFamily, SessionMsg},
                header::FrameHeader,
                session::HandoffResponsePayload,
            };
            // Replay the OLD captured hmac (bound to challenge1).
            let body = HandoffResponsePayload {
                hmac: captured_hmac,
            }
            .encode();
            let mut hdr = FrameHeader::new(
                FrameFamily::Session as u8,
                SessionMsg::HandoffResponse as u16,
            );
            hdr.body_len = body.len() as u32;
            let mut wire = encode_header(&hdr).to_vec();
            wire.extend_from_slice(&body);
            c2.write_all(&wire).await.unwrap();
        }
        let outcome2 = accept2.await.unwrap();
        match outcome2 {
            PeekOutcome::Drop(r) => assert!(
                r.contains("HMAC"),
                "replayed response must drop on HMAC mismatch, got: {r}"
            ),
            _ => panic!("replayed response MUST be rejected (T1 anti-replay)"),
        }
        // The legit pending entry survives the failed attacker attempt
        // (peek-not-consume on failure).
        assert!(
            handoff.peek(&session_id).is_some(),
            "a failed/forged response must NOT consume the pending entry"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn peek_and_dispatch_non_handoff_returns_prefixed_handshake_stream() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        use veil_proto::{
            codec::encode_header,
            family::{FrameFamily, SessionMsg},
            header::FrameHeader,
        };

        let handoff = HandoffRegistry::new();
        let swap_reg = SessionSwapRegistry::new();

        // A normal OVL1 Hello frame header (regular handshake start).
        let mut hdr = FrameHeader::new(FrameFamily::Session as u8, SessionMsg::Hello as u16);
        hdr.body_len = 0;
        let hdr_bytes = encode_header(&hdr);

        let (mut client, server) = tokio::io::duplex(1024);
        client.write_all(&hdr_bytes).await.unwrap();
        client.write_all(b"REST-OF-HANDSHAKE").await.unwrap();

        let outcome = peek_and_dispatch(server, &handoff, &swap_reg, 2).await;
        let mut stream = match outcome {
            PeekOutcome::Handshake(s) => s,
            other => panic!(
                "expected Handshake, got {:?}",
                match other {
                    PeekOutcome::HandoffBound => "HandoffBound",
                    PeekOutcome::Drop(_) => "Drop",
                    _ => "unreachable",
                }
            ),
        };

        // The PrefixedStream must replay the full HEADER_SIZE header
        // bytes (24) before the inner stream's "REST-OF-HANDSHAKE".
        let mut replayed = [0u8; veil_proto::header::HEADER_SIZE];
        stream.read_exact(&mut replayed).await.unwrap();
        assert_eq!(
            &replayed[..],
            &hdr_bytes[..],
            "PrefixedStream must replay the peeked header"
        );
        let mut rest = [0u8; 17];
        stream.read_exact(&mut rest).await.unwrap();
        assert_eq!(&rest, b"REST-OF-HANDSHAKE");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn peek_and_dispatch_handoff_with_bad_response_hmac_drops() {
        let handoff = std::sync::Arc::new(HandoffRegistry::new());
        let swap_reg = std::sync::Arc::new(SessionSwapRegistry::new());

        let session_id = [0x33u8; 32];
        let peer_id: NodeId = [0x44u8; 32].into();
        let nonce = [0x55u8; 32];
        let rx_key = [0x11u8; 32];
        handoff.insert(session_id, peer_id, nonce, rx_key);
        let (tx, mut rx) = tokio::sync::mpsc::channel::<BoxIoStream>(1);
        let _guard = swap_reg.register(session_id, [0x99u8; 32].into(), tx, [0u8; 32]);

        let (mut client, server) = tokio::io::duplex(1024);
        let h = std::sync::Arc::clone(&handoff);
        let sr = std::sync::Arc::clone(&swap_reg);
        let accept = tokio::spawn(async move { peek_and_dispatch(server, &h, &sr, 2).await });

        send_attach(&mut client, session_id).await;
        let challenge = read_challenge(&mut client).await;
        // Attacker answers with the WRONG key (does not hold the session key).
        send_response(&mut client, [0xFFu8; 32], session_id, challenge).await;

        let outcome = accept.await.unwrap();
        match outcome {
            PeekOutcome::Drop(r) => assert!(
                r.contains("HMAC"),
                "drop reason should mention HMAC mismatch, got {r}"
            ),
            _ => panic!("expected Drop for bad-response-HMAC handoff"),
        }
        assert!(
            rx.try_recv().is_err(),
            "bad response HMAC must NOT leak a stream into swap_rx"
        );
        // audit cycle-6 (T1): a forged response must NOT consume the pending
        // entry (peek-not-consume on failure) — so the legit initiator can
        // still complete a handoff.
        assert!(
            handoff.peek(&session_id).is_some(),
            "a forged response must NOT consume the legit pending entry"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn peek_and_dispatch_handoff_for_unknown_session_drops() {
        let handoff = std::sync::Arc::new(HandoffRegistry::new()); // empty
        let swap_reg = std::sync::Arc::new(SessionSwapRegistry::new()); // empty

        let session_id = [0x99u8; 32];
        let (mut client, server) = tokio::io::duplex(1024);
        let h = std::sync::Arc::clone(&handoff);
        let sr = std::sync::Arc::clone(&swap_reg);
        let accept = tokio::spawn(async move { peek_and_dispatch(server, &h, &sr, 2).await });

        // Bare attach for an unknown session — receiver has no pending entry,
        // so it must drop BEFORE issuing a challenge.
        send_attach(&mut client, session_id).await;

        let outcome = accept.await.unwrap();
        assert!(
            matches!(outcome, PeekOutcome::Drop(_)),
            "unknown session_id must drop"
        );
    }
}
