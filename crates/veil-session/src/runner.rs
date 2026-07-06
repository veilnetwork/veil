//! OVL1 session runner — post-handshake frame loop.
//!
//! After an OVL1 session is established (handshake complete, peer_id known)
//! `SessionRunner::run` takes over the stream and dispatches every incoming
//! frame through `FrameDispatcher`.
//!
//! Frame framing:
//! ```text
//! [24-byte FrameHeader] [body_len bytes body]
//! ```
//! After dispatch, if the dispatcher returns a `Response`, it is written back
//! to the stream immediately. Violations are logged and counted but do not
//! close the session by default; they are forwarded to `ViolationTracker`.

use std::sync::{Arc, Mutex};
use veil_util::{lock, rlock, wlock};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::mpsc,
};

use veil_abuse::{BanList, ViolationTracker};
use veil_crypto::{
    kex,
    session_cipher::{SessionCipher, frame_aad},
    session_kdf,
};
use veil_observability::{NodeLogger, NodeMetrics};
use veil_proto::{
    budget::{MLKEM_REKEY_BYTES_THRESHOLD, MLKEM_REKEY_TIME_THRESHOLD_SECS},
    codec::{decode_header, decode_header_with_limit, encode_header},
    family::{ControlMsg, DiscoveryMsg, FrameFamily, SessionMsg},
    header::FrameHeader,
    session::{MlKemRekeyEkPayload, RekeyPayload},
};
use veil_transport::BoxIoStream;
use veil_types::NodeIdBytes;

use crate::dispatcher_sink::DispatchResult;
use crate::outbox::OutboxRequest;
use crate::priority_queue::PriorityQueue;
use crate::tx_registry::PriorityFrame;

/// Shared map from peer node-id to ephemeral ML-KEM decapsulation-key seed
/// (Phase 6 slice 6h).  Used by `SessionRunner` and
/// `CryptoContext`/`FrameDispatcher`.
///
/// # Memory hygiene
///
/// Values are `SensitiveBytesN<64>` — pages pinned via `mlock(2)` when
/// `RLIMIT_MEMLOCK` permits, fall back to `Zeroizing<Vec<u8>>` otherwise.
/// Closes the swap-to-disk vector for session-lifetime ephemeral PQ
/// secrets: if pages holding a DK seed land on disk during the
/// session, anyone with read access to the swap partition can decapsulate
/// any E2E ciphertext sent to this node within that session window.
///
/// Insertion takes a raw `[u8; 64]` (the output of
/// `veil_e2e::generate_keypair`) and wraps it via
/// `SensitiveBytesN::from_bytes`; reads use `.as_array()` to expose a
/// `&[u8; 64]` view to the ml-kem decap call.
pub type PerSessionMlKemDk = Arc<
    Mutex<
        std::collections::HashMap<
            NodeIdBytes,
            veil_util::sensitive_bytes::SensitiveBytesN<{ veil_e2e::DK_SEED_BYTES }>,
        >,
    >,
>;

// ── BudgetGuard ───────────────────────────────────────────────────────────────

/// RAII guard that decrements `pow_active_difficulty` when dropped.
///
/// Ensures the difficulty budget is always released — even if the enclosing
/// async task is cancelled or a future branch returns early — preventing a
/// permanent budget leak.
pub struct BudgetGuard {
    budget: Arc<std::sync::atomic::AtomicU64>,
    difficulty: u64,
}

impl Drop for BudgetGuard {
    fn drop(&mut self) {
        // Audit batch 2026-05-24 (L1): `Release` ordering ensures the
        // decrement is globally visible BEFORE any subsequent budget
        // read (e.g. a hot-path `budget > 0` check on another thread).
        // `Relaxed` was sufficient under single-thread executor but
        // multi-thread runtime can observe stale-by-one values.
        self.budget
            .fetch_sub(self.difficulty, std::sync::atomic::Ordering::Release);
    }
}

// Slice 31: `AliasGuard` (now `SessionAliasGuard`) + its constructor
// moved to `session::session_alias_guard` for consistency with slices 22-30.
// See module-doc there for rationale.

// ── await_next_input ──────────────────────────────────────────────────────────

/// Return type [`await_next_input`].
pub enum NextInput {
    /// First byte of the next incoming frame.
    Byte(u8),
    /// A priority-tagged frame was received from the outbox.
    OutboxFrame(PriorityFrame),
    /// An RPC request arrived in the rpc_outbox while waiting.
    RpcRequest(OutboxRequest),
    /// A timer (keepalive or idle-check) fired — caller should loop back.
    Timer,
    /// a replacement `BoxIoStream` arrived on `swap_rx`. The
    /// main loop swaps `self.stream` and loops back, keeping all AEAD
    /// state intact.
    SwapStream(BoxIoStream),
    /// The stream read side returned EOF or an I/O error while waiting for
    /// the first byte of the next frame.
    ReadClosed(String),
    /// The dedicated writer task exited, usually because the socket write
    /// half returned an error or stalled.
    WriterClosed,
}

/// Wait for the next interesting event:
///
/// a byte arriving on `stream` (first byte of a frame)
/// a frame becoming available in `outbox` (when `Some`)
/// a timer expiring at `sleep_until` (when `Some`), or
/// a replacement stream arriving on `swap_rx`.
///
/// Returns immediately with whichever event fires first. Uses
/// `std::future::pending` for absent sources so a single `tokio::select!`
/// handles all optional-combination cases without duplication.
async fn await_next_input(
    read_half: &mut tokio::io::ReadHalf<BoxIoStream>,
    outbox: Option<&mut mpsc::Receiver<PriorityFrame>>,
    rpc_outbox: Option<&mut mpsc::Receiver<OutboxRequest>>,
    swap_rx: Option<&mut mpsc::Receiver<BoxIoStream>>,
    sleep_until: Option<tokio::time::Instant>,
    wire_tx: &mpsc::Sender<veil_bufpool::PooledShared>,
) -> NextInput {
    use std::future::pending;
    use tokio::io::AsyncReadExt as _;

    tokio::select! {
        r = read_half.read_u8() => match r {
            Ok(b)  => NextInput::Byte(b),
            Err(e) => NextInput::ReadClosed(e.to_string()),
        },
        Some(frame) = async {
            match outbox {
                Some(rx) => rx.recv().await,
                None     => pending::<Option<PriorityFrame>>().await,
            }
        } => NextInput::OutboxFrame(frame),
        Some(req) = async {
            match rpc_outbox {
                Some(rx) => rx.recv().await,
                None     => pending::<Option<OutboxRequest>>().await,
            }
        } => NextInput::RpcRequest(req),
        Some(new_stream) = async {
            match swap_rx {
                Some(rx) => rx.recv().await,
                None     => pending::<Option<BoxIoStream>>().await,
            }
        } => NextInput::SwapStream(new_stream),
        _ = async {
            match sleep_until {
                Some(deadline) => tokio::time::sleep_until(deadline).await,
                None           => pending::<()>().await,
            }
        } => NextInput::Timer,
        // b: monitor writer task health. If the writer
        // task's `wire_rx` is dropped (writer exited on write error
        // or timeout), this future resolves immediately and the main
        // loop sees `Closed` on the next iteration — same teardown
        // path as a peer FIN on the read side. Without this arm
        // a runner with no pending outbound traffic would not notice
        // the writer dying (test scenario: one frame to send, write
        // fails immediately, writer exits, but main loop is parked
        // on `await_next_input` waiting for input that never comes).
        _ = wire_tx.closed() => NextInput::WriterClosed,
    }
}

// ── SessionRunner ─────────────────────────────────────────────────────────────

/// Outcome from `decrypt_frame_body`: either the raw bytes are already
/// the plaintext (no-cipher path, rare — only handshake-leading
/// b bufpool: outcome from `decrypt_frame_body_in_place`. Allows
/// the caller to borrow plaintext directly from the input buffer in
/// the common case (no plaintext allocation).
///
/// The earlier `DecryptOutcome` enum + `decrypt_frame_body` heap-alloc
/// fallback were the rollback path for the `bufpool-plaintext` feature
/// flag; both removed after validation completed. If a rollback ever
/// needed restore from git history.
pub enum DecryptInPlaceOutcome {
    /// No cipher or empty body — caller uses the input slice as-is.
    Passthrough,
    /// In-place decrypt succeeded — input buffer now contains plaintext
    /// (length shrunk by `AEAD_OVERHEAD`). Zero-allocation success path.
    InPlace,
    /// Rekey-grace fallback fired — prev-cipher allocated a new plaintext
    /// buffer. Rare; only fires during the 30 s window post-rekey while
    /// the prev cipher remains armed in `RekeyRxGraceBuffer`.
    GracePlaintext(Vec<u8>),
}

/// Session cipher state — both directions plus the ML-KEM key material
/// that participates in hybrid-rekey re-derivation.
///
/// The two symmetric ciphers (ChaCha20-Poly1305) hold per-direction
/// nonce counters; on rekey they are replaced atomically with the
/// freshly-derived keys.  The ML-KEM entries — `peer_mlkem_keys` (peer's
/// public encapsulation cache) and `per_session_mlkem_dk` (this node's
/// ephemeral decapsulation seed) — feed the hybrid-rekey path that
/// mixes a post-quantum shared secret into the new symmetric keys.
///
/// All four are `Option` so test fixtures and minimal-runtime builds can
/// run without crypto (`None` everywhere = pure plaintext frames, used
/// by a handful of decode/encode unit tests).
pub struct CryptoState {
    /// AEAD cipher for outgoing frame bodies; `None` when encryption
    /// is not in use (handshake phase or no-crypto tests).
    pub tx_cipher: Option<SessionCipher>,
    /// AEAD cipher for incoming frame bodies; `None` when encryption
    /// is not in use.
    pub rx_cipher: Option<SessionCipher>,
    /// Peer ML-KEM-768 encapsulation-key cache.  When the peer sends a
    /// `MlKemRekeyEk` frame, the runner updates
    /// `peer_mlkem_keys[peer_id]` to the new encapsulation key so
    /// subsequent E2E messages to this peer use the rotated key.
    pub peer_mlkem_keys: Option<Arc<std::sync::RwLock<veil_e2e::PeerMlKemCache>>>,
    /// Per-session ephemeral ML-KEM-768 decapsulation-key seed.  When
    /// we complete our own `MlKemRekeyEk` → `MlKemRekeyAck` exchange,
    /// `per_session_mlkem_dk[peer_id]` is updated to the new DK seed
    /// so the dispatcher uses it for decryption of incoming E2E
    /// messages from this peer.  Shared `Arc` with `CryptoContext`.
    pub per_session_mlkem_dk: Option<PerSessionMlKemDk>,
}

/// Hot-standby transport-swap state for one session.
///
/// When the primary transport degrades (write errors past
/// `auto_trigger_after_write_errors`), the auto-swap controller spawns a
/// warm-probe task that dials an alt_uri and ships the new stream into
/// `swap_rx`.  The runner's main loop drains `swap_rx` between frames
/// and replaces `self.stream` while preserving AEAD state — a pure
/// transport-level handover, no OVL1 re-handshake.
///
/// All fields are `Option` so test fixtures and minimal-runtime builds
/// can leave hot-standby disabled without scaffolding.  Production
/// runtimes wire all four pieces.
pub struct HotStandbyState {
    /// Inbox for a replacement [`BoxIoStream`].  `None` disables auto-
    /// swap (the runner exits on the first transport error).
    pub swap_rx: Option<mpsc::Receiver<BoxIoStream>>,
    /// Per-runtime handoff registry — `HandoffInit` frames register a
    /// pending entry keyed by `session_id` so the accept-side warm-
    /// socket task can bind it after HMAC verification.  `None` leaves
    /// the runner handoff-oblivious (frames tolerated but ignored).
    pub handoff_registry: Option<std::sync::Arc<crate::handoff::HandoffRegistry>>,
    /// Per-runtime `session_id → HandoffAck waiter` map.  Initiators
    /// register before sending `HandoffInit`; the runner routes
    /// incoming `HandoffAck` frames to the matching waiter.  `None`
    /// drops late acks (peer falls back to registry-TTL timeout).
    pub handoff_ack_waiters: Option<std::sync::Arc<crate::handoff::HandoffAckWaiters>>,
    /// Auto-swap controller — spawned warm-probe + flap-damping.
    /// `None` disables the auto-trigger feature.
    pub controller: Option<std::sync::Arc<crate::hot_standby::HotStandbyController>>,
    /// Consecutive write-error count required to fire the controller.
    /// `0` disables the counter even when a `controller` is wired.
    /// Triggered AFTER a primary write fails — works for half-dead
    /// transport states (outbound blocked, inbound still reading; a
    /// common Windows Firewall scenario).  A proactive RTT-based
    /// trigger is a future enhancement.
    pub auto_trigger_after_write_errors: u32,
}

/// Decide whether the automatic hot-standby path should fire for `reason`.
///
/// Two gates:
///   * `[hot_standby] enabled` — the master switch.  (Historically this flag
///     was never read, so warm probes fired regardless of config.)
///   * `reason` — `primary_closed` means the primary's READ side hit EOF
///     (the peer closed / the transport died).  The first handoff frame
///     (`HandoffInit`) must still travel over that primary, so a swap can't
///     reach the gone peer: it only loses the race against the
///     `session_tx_registry` unregister and emits a misleading `swap_failed`
///     WARN, while the outbound reconnect path already recovers the session.
///     Every other auto reason stays eligible — in particular `writer_closed`
///     and the write-error reasons target the half-dead "outbound blocked,
///     inbound alive" case hot-standby is designed to rescue.
pub(crate) fn hot_standby_should_auto_fire(enabled: bool, reason: &str) -> bool {
    enabled && reason != "primary_closed"
}

/// Per-episode warm-probe swap-attempt ceiling for the M5 re-eval teardown.
pub(crate) const KEEPALIVE_SWAP_ATTEMPT_CEILING: u32 = 2;

/// Unacked-probe age (as a multiple of `probe_timeout`) past which a FRESH
/// genuine-RX no longer vetoes the re-eval reap. The dispatcher answers every
/// inbound Keepalive with an immediate REALTIME KeepaliveAck over a reliable
/// transport, so a probe ledger that stays unacked for this many whole
/// windows *while genuine inbound keeps flowing* is proof of a
/// one-directional TX wedge (our send direction black-holes, RX alive) — the
/// half-dead state the plain `genuine_stale` gate was masking. 3 windows
/// (90 s at the default 30 s interval) sits far above any legitimate
/// ack-latency (TCP retransmit under loss is seconds, not minutes) so only a
/// truly wedged TX trips it.
pub(crate) const TX_WEDGE_PROBE_MULTIPLE: u32 = 3;

/// Pure teardown decision for the re-evaluable keepalive-probe-timeout path.
/// Reaps ONLY when the probe ledger is stale AND failover is exhausted (no
/// warm probe OR the swap-attempt ceiling is hit) AND either (a) no genuine
/// inbound arrived within the window — the peer-gone M5 zombie — or (b) the
/// ledger has been unacked for [`TX_WEDGE_PROBE_MULTIPLE`] whole windows —
/// the one-directional TX wedge where live inbound would otherwise mask a
/// black-holed send direction forever. `probe_timeout == 0` short-circuits to
/// false (keepalive-disabled sessions are never reaped). Inputs are only
/// Durations + scalars: no `SessionRunner`, no clock, no I/O.
#[must_use]
pub(crate) fn should_reeval_teardown(
    probe_age: std::time::Duration,
    probe_timeout: std::time::Duration,
    swap_attempts: u32,
    ceiling: u32,
    last_genuine_rx_age: std::time::Duration,
    hot_standby_ok: bool,
) -> bool {
    if probe_timeout.is_zero() {
        return false;
    }
    let probe_stale = probe_age >= probe_timeout;
    let genuine_stale = last_genuine_rx_age >= probe_timeout;
    let tx_wedged = probe_age >= probe_timeout * TX_WEDGE_PROBE_MULTIPLE;
    let no_failover = !hot_standby_ok || swap_attempts >= ceiling;
    probe_stale && (genuine_stale || tx_wedged) && no_failover
}

/// Session rekey trigger thresholds.
///
/// Either threshold firing alone triggers an X25519 ephemeral rekey:
/// `bytes_threshold` catches high-traffic sessions before nonce exhaustion
/// (2⁶⁴ frames before ChaCha20 wrap); `time_threshold_secs` catches
/// low-traffic but long-lived sessions before bytes alone would force it.
/// Sourced from `SessionConfig.rekey_bytes_threshold` / `rekey_time_
/// threshold_secs` at construction.
#[derive(Clone, Copy, Debug)]
pub struct RekeyConfig {
    /// Cumulative byte threshold (tx + rx) at which to initiate rekey.
    /// Default `REKEY_BYTES_THRESHOLD`.
    pub bytes_threshold: u64,
    /// Elapsed-seconds threshold at which to initiate rekey.
    /// Default `REKEY_TIME_THRESHOLD_SECS`.
    pub time_threshold_secs: u64,
}

/// Battery-aware keepalive configuration.
///
/// Mobile clients adapt their keepalive cadence to battery level so a
/// foregrounded session doesn't drain a phone at the same rate as a
/// desktop's continuous polling.  Two thresholds (low, medium) gate
/// multiplicative scale factors applied to `base_keepalive_interval`.
#[derive(Clone, Debug)]
pub struct MobileConfig {
    /// Base keepalive interval before any battery-based scaling.
    /// On construction this equals the runner's `keepalive_interval`;
    /// keeping it separate lets us recompute the effective interval on
    /// every battery-level change without losing the source value.
    pub base_keepalive_interval: std::time::Duration,
    /// Multiplier applied when battery < [`Self::battery_threshold_low`].
    /// Larger value = longer keepalive interval = more aggressive
    /// power saving.
    pub battery_keepalive_scale_low: f32,
    /// Multiplier applied when battery < [`Self::battery_threshold_medium`]
    /// but >= [`Self::battery_threshold_low`].
    pub battery_keepalive_scale_medium: f32,
    /// Battery percentage below which `scale_low` engages (default 20).
    pub battery_threshold_low: u8,
    /// Battery percentage below which `scale_medium` engages (default 50).
    pub battery_threshold_medium: u8,
}

/// Drives the post-handshake OVL1 message loop for one session.
pub struct SessionRunner {
    pub stream: BoxIoStream,
    pub peer_id: NodeIdBytes,
    pub dispatcher: Arc<dyn crate::dispatcher_sink::DispatcherSink>,
    pub logger: Arc<NodeLogger>,
    pub metrics: Option<Arc<NodeMetrics>>,
    pub ban_list: Arc<Mutex<BanList>>,
    pub violation_tracker: Arc<Mutex<ViolationTracker>>,
    /// Session cipher state: AEAD ciphers (tx + rx) plus ML-KEM key
    /// material that participates in hybrid-rekey re-derivation.
    pub crypto: CryptoState,
    /// Outbox — priority-tagged frames queued by the runtime to be sent to this
    /// peer. `None` if the runtime does not use the outbox mechanism.
    pub outbox: Option<mpsc::Receiver<PriorityFrame>>,
    /// RPC request outbox — carries pre-encoded frames with response oneshots.
    /// The runner writes each frame to the wire, then fulfils the oneshot
    /// when a matching `FIND_NODE_RESPONSE` arrives.
    pub rpc_outbox: Option<mpsc::Receiver<OutboxRequest>>,
    /// How often to send a Keepalive frame. Zero means keepalive is disabled
    /// (no Keepalive sent, no idle timeout enforced).
    pub keepalive_interval: std::time::Duration,
    /// Close the session if no frame is received within this window.
    /// Only enforced when keepalive_interval > 0.
    pub idle_timeout: std::time::Duration,
    /// Session identifier derived during the handshake; used as chaining salt
    /// when deriving new keys after a rekey. All-zero disables rekey.
    pub session_id: [u8; 32],
    /// This node's 32-byte BLAKE3 node ID — required for rekey KDF.
    pub local_node_id: NodeIdBytes,
    /// Maximum number of in-flight RPC response slots (default 256).
    pub max_pending_responses: usize,
    /// Expiry for in-flight RPC response slots (default 30 s).
    pub pending_response_ttl: std::time::Duration,
    /// Per-session maximum incoming frame body size (default 1 MiB, hard
    /// ceiling 16 MiB). Frames that claim a larger body are rejected
    /// immediately to prevent memory exhaustion.
    pub max_frame_body: u32,
    /// Session rekey trigger thresholds (bytes + time).
    pub rekey: RekeyConfig,
    /// WRR weights for the 4 outbound traffic classes `[RealTime=8, Interactive=4
    /// Bulk=2, Background=1]`. Sourced from `SessionConfig.qos_weights`.
    pub qos_weights: [u32; 4],
    /// Battery-aware keepalive configuration: base interval plus scale
    /// factors and thresholds for adaptive backoff on low-battery devices.
    pub mobile: MobileConfig,

    // the former `negotiated_caps` field was removed — single
    // protocol version, all features always on. Callers that used to query
    // `.chunking` etc. inline `true` directly.

    // ── session resumption ──────────────────────────────────────────
    /// Pre-encrypted `SESSION_TICKET` blob to send to the peer at session start.
    ///
    /// Set by the server-side runtime when `session_resumption` is negotiated;
    /// `None` for the client side and for sessions where resumption is not supported.
    /// The runner sends this frame immediately at the start of `run`, before
    /// entering the main dispatch loop.
    pub ticket_to_send: Option<Vec<u8>>,

    /// Shared storage for per-peer resumption tickets received during this session.
    ///
    /// When the peer sends a `SESSION_TICKET` frame, the runner stores the blob
    /// in `peer_tickets[peer_id]` so that the next reconnect can present it.
    /// `None` in tests and when resumption is disabled.
    #[allow(clippy::type_complexity)]
    pub peer_tickets: Option<
        Arc<Mutex<std::collections::HashMap<NodeIdBytes, veil_proto::session::ClientTicketEntry>>>,
    >,

    /// Raw session TX key, RX key, and session_id from the handshake (client side only).
    ///
    /// Populated for outbound (client-role) sessions so that when the peer sends a
    /// `SESSION_TICKET` frame, the runner can build a `ClientTicketEntry` that
    /// includes both the opaque blob AND the client's own restoration keys.
    /// `None` for inbound (server-role) sessions.
    pub raw_session_keys: Option<([u8; 32], [u8; 32], [u8; 32])>, // (tx_key, rx_key, session_id)

    /// Remote peer's base64-encoded public key from the original handshake.
    /// Stored in `ClientTicketEntry` so that fast-path resumption can
    /// reconstruct `OvlHandshakeResult.public_key` without re-exchanging IDENTITY.
    /// `None` for inbound (server-role) sessions.
    pub peer_public_key: Option<String>,
    /// Remote peer's nonce string from the original handshake.
    pub peer_nonce: Option<String>,

    /// Hot-standby transport-swap state: swap inbox, handoff registries,
    /// auto-trigger controller, and write-error threshold.
    pub hot_standby: HotStandbyState,

    /// **Primary transport URI** of this session (the URI the outbound
    /// connector dialed, or `None` if this is an inbound-accepted
    /// session where the local side doesn't know a dialable URI for
    /// the peer).
    ///
    /// Used by the rotation-deadline → hot-standby trigger path
    /// (Q.7 audit batch) to dial **the same URI again** for true
    /// zero-gap make-before-break when no separate `alt_uri` is
    /// configured.  Without this, rotation against a single-URI peer
    /// falls back to the legacy "close + reconnect" path (~1 s gap).
    ///
    /// Inbound sessions leave it `None` — the local side never
    /// initiates rotation from the accept side (the peer who dialed us
    /// is responsible for its own connection lifecycle); the field
    /// being absent simply makes `fire_hot_standby_trigger` fall back
    /// to the `alt_uri_for(peer_id)` lookup as before.
    pub primary_uri: Option<String>,
}

impl Drop for SessionRunner {
    /// Zeroize the plaintext copy of the session keys on drop. `SessionKeys`
    /// and `SessionCipher` are already `ZeroizeOnDrop`, but `raw_session_keys`
    /// is a separate plaintext copy of tx/rx (kept for handoff + ticket
    /// issuance) that was left to drop as raw bytes — recoverable from freed
    /// memory / swap / a core dump. Wipe tx/rx here (session_id is not secret).
    /// (audit cycle-2 MEDIUM: inconsistent key zeroization.)
    fn drop(&mut self) {
        use zeroize::Zeroize;
        if let Some((tx, rx, _session_id)) = self.raw_session_keys.as_mut() {
            tx.zeroize();
            rx.zeroize();
        }
    }
}

/// per-`write_all` deadline applied to the session's outbound
/// socket writes inside the dedicated writer task (see `spawn_writer_task`).
/// On a healthy edge a write completes in < 4 s at typical inter-VPS rates
/// (17-24 KB/s, ≤ 64 KB frames); 30 s gives an order of magnitude slack
/// for transient WAN spikes and TLS-record alignment delays while still
/// breaking through a half-broken peer's stuck send buffer within
/// keepalive cadence. When the writer task hits this deadline it exits;
/// its `wire_rx` then drops, the main loop's `wire_tx.try_send` starts
/// returning Err, and the session terminates cleanly via the existing
/// `on_primary_write_error` path — same self-healing behaviour as the
/// earlier band-aid, but now without ALSO blocking the read path.
pub const WRITE_PROGRESS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// cap how many priority-queue frames the runner pushes to
/// the writer task per outer-loop iteration. Without this cap, a deep
/// pq fed by chat-node-style burst load monopolises the loop iteration
/// and delays the next `await_next_input` (so reads of incoming frames
/// are starved by our own outbound flushing). 16 frames per drain pass
/// is small enough that the read side gets air on every iteration but
/// large enough that latency-sensitive frames at the head of the queue
/// still flush promptly. Combined with the writer-task split below
/// this also caps the burst rate at which the wire channel fills —
/// prevents a single-iteration spike from monopolising channel slots
/// before the writer task drains them.
// Phase E22 (2026-05-22): bumped from 16 to 256 for high-throughput
// workloads (ogate-tunnel, bulk-transfer apps).  At 16 the priority-queue
// dropped 64K frames in 12 s during iperf through ogate — drain couldn't
// match enqueue rate.  256 absorbs typical 2 Gbps-per-peer bursts
// (~167K fps × 1.5 ms tokio-tick = ~250 frames) without overrun.  Worst-case
// burst latency: 256 × ~3 µs/frame = ~750 µs per drain pass, still
// well below the cover-traffic / keepalive scheduling granularity.
pub const PQ_DRAIN_FRAMES_PER_PASS: usize = 256;

/// bounded capacity of the `wire_tx`/`wire_rx` channel that
/// connects the runner's main loop (read + dispatch) to the dedicated
/// writer task. Sized to absorb a moderate burst from a chat-node-style
/// fan-out (8 peers × 2 in-flight frames per peer = 16, ×16 for safety
/// margin = 256) while bounding worst-case memory at peer ≤
/// `256 × max_frame_body` ≈ 4 GB only if we pessimistically assume every
/// queued frame is at the 16 MB max. In practice typical wire frames
/// are 60-300 B (control) to 64 KB (chat data), so steady-state memory
/// is well under 16 MB. When full, `try_send` returns Err — main loop
/// drops the frame with metric `inc_session_wire_dropped`; the writer
/// catches up and the queue refills. Critical: this NEVER blocks the
/// main loop, so reads always make progress.
pub const WIRE_CHANNEL_CAPACITY: usize = 256;

/// writer task — owns the `WriteHalf<BoxIoStream>` and
/// drains pre-encrypted/pre-coalesced wire bytes pushed onto it from
/// the runner's main loop. Each `write_all` is wrapped in a
/// [`WRITE_PROGRESS_TIMEOUT`] deadline; on expiry the task exits, its
/// `wire_rx` drops, and the runner sees `wire_tx.try_send` return Err
/// on its next push — at which point the main loop closes the session
/// via `on_primary_write_error`.
///
/// The task NEVER reads the socket, NEVER touches AEAD ciphers, and
/// holds NO state beyond the write half + receiver — so it is impossible
/// for the writer to be transitively waiting on anything the runner
/// owns. In particular: the previous design's deadlock (writer blocked
/// on TCP send buffer because peer's recv buffer is full because peer
/// is itself blocked on its own send buffer because we haven't drained
/// our recv buffer because we are blocked on our writer) cannot form —
/// our reader is now in a separate task path that always drains.
async fn writer_task(
    mut write_half: tokio::io::WriteHalf<BoxIoStream>,
    mut wire_rx: mpsc::Receiver<veil_bufpool::PooledShared>,
    metrics: Option<Arc<NodeMetrics>>,
    logger: Arc<NodeLogger>,
    peer_id_short: String,
) {
    while let Some(bytes) = wire_rx.recv().await {
        let wire_len = bytes.len();
        match tokio::time::timeout(WRITE_PROGRESS_TIMEOUT, write_half.write_all(&bytes)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                // Underlying write failed — peer FIN, RST, etc. Exit.
                logger.warn(
                    "session.writer.write_error",
                    format!("peer_id={peer_id_short} len={wire_len} error={e}"),
                );
                break;
            }
            Err(_) => {
                if let Some(m) = &metrics {
                    m.inc_session_write_stalled();
                }
                logger.warn(
                    "session.writer.stalled",
                    format!(
                        "peer_id={peer_id_short} write_all exceeded {:?} — closing writer; \
                         main loop will see wire channel disconnect on next push",
                        WRITE_PROGRESS_TIMEOUT,
                    ),
                );
                break;
            }
        }
    }
    // wire_rx closed (main loop dropped wire_tx) OR write error — flush
    // best-effort and return. Main loop's `await` on the writer JoinHandle
    // unblocks; session teardown proceeds.
    let _ = write_half.shutdown().await;
}

/// Spawn a writer task tied to one `WriteHalf<BoxIoStream>` + one
/// `wire_rx`. Returns the JoinHandle so the main loop can `await` it
/// at session teardown (or drop on hot-standby swap to release the
/// task's owned WriteHalf).
pub fn spawn_writer_task(
    write_half: tokio::io::WriteHalf<BoxIoStream>,
    wire_rx: mpsc::Receiver<veil_bufpool::PooledShared>,
    metrics: Option<Arc<NodeMetrics>>,
    logger: Arc<NodeLogger>,
    peer_id_short: String,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(writer_task(
        write_half,
        wire_rx,
        metrics,
        logger,
        peer_id_short,
    ))
}

/// a "broken" sentinel `BoxIoStream` returned from
/// `std::mem::replace` when the runner takes ownership of the real
/// stream at startup. Never actually used for I/O — read/write paths
/// in the new design go through the split (`ReadHalf` / writer task).
/// On any I/O attempt this returns an immediate `BrokenPipe` error.
pub fn broken_stream_sentinel() -> BoxIoStream {
    let (a, b) = tokio::io::duplex(1);
    drop(b); // closes the pair; any read/write on `a` returns BrokenPipe.
    Box::new(a)
}

impl SessionRunner {
    /// push pre-encrypted wire bytes to the writer task.
    /// Returns `Ok` on success, `Err` if the channel is full
    /// (writer falling behind — we drop the frame with metric) or
    /// disconnected (writer task exited — session is over). Both error
    /// cases are caller-actionable: full → continue/drop, disconnected
    /// → caller invokes `on_primary_write_error` and exits.
    ///
    /// This is the SOLE way the runner pushes outbound bytes after the
    /// reader/writer split. It NEVER blocks the main
    /// loop — `try_send` is sync. Compare to the prior architecture
    /// where every `self.stream.write_all.await` could block the
    /// whole loop (read AND dispatch) for up to 30 s during the
    /// symmetric-deadlock window observed on testnet.
    fn push_wire(
        wire_tx: &mpsc::Sender<veil_bufpool::PooledShared>,
        bytes: veil_bufpool::PooledShared,
        metrics: &Option<Arc<NodeMetrics>>,
    ) -> Result<(), mpsc::error::TrySendError<veil_bufpool::PooledShared>> {
        match wire_tx.try_send(bytes) {
            Ok(()) => Ok(()),
            Err(e @ mpsc::error::TrySendError::Full(_)) => {
                if let Some(m) = metrics {
                    m.inc_session_wire_dropped();
                }
                Err(e)
            }
            Err(e @ mpsc::error::TrySendError::Closed(_)) => {
                // Writer task exited (timeout or peer FIN). Caller
                // closes session via on_primary_write_error.
                Err(e)
            }
        }
    }

    /// Emit the pre-encrypted SESSION_TICKET blob (if queued by the
    /// caller via `ticket_to_send`) before the main loop starts.
    ///
    /// Returns `Ok` if a ticket was sent successfully OR if no
    /// ticket was queued. Returns `Err` if a cipher or wire-
    /// channel error happened — caller must propagate the early-exit
    /// to match the original inline `return`.
    fn send_pending_session_ticket(
        &mut self,
        wire_tx: &mpsc::Sender<veil_bufpool::PooledShared>,
        write_error_count: &mut crate::write_error_tracker::WriteErrorTracker,
    ) -> Result<(), ()> {
        let Some(blob) = self.ticket_to_send.take() else {
            return Ok(());
        };
        let mut hdr = veil_proto::header::FrameHeader::new(
            veil_proto::family::FrameFamily::Session as u8,
            veil_proto::family::SessionMsg::Ticket as u16,
        );
        hdr.body_len = blob.len() as u32;
        let mut frame = encode_header(&hdr).to_vec();
        frame.extend_from_slice(&blob);
        let wire = if let Some(cipher) = self.crypto.tx_cipher.as_mut() {
            match apply_tx_cipher(&frame, cipher) {
                Some(enc) => enc,
                None => return Err(()),
            }
        } else {
            veil_bufpool::pooled_shared_from_vec(frame)
        };
        if Self::push_wire(wire_tx, wire, &self.metrics).is_err() {
            self.on_primary_write_error(write_error_count);
            return Err(());
        }
        Ok(())
    }

    /// Register session aliases (compact 8-byte handles for
    /// RouteAnnounceAliased / RouteWithdrawAliased gossip) and return
    /// a guard so the runner's `Drop` cleanup automatically
    /// unregisters.  Slice 31: delegates to
    /// [`crate::session_alias_guard::register_session_aliases_with_drop_guard`]
    /// — see there for full docs.
    fn register_session_aliases_with_drop_guard(
        &self,
    ) -> Option<crate::session_alias_guard::SessionAliasGuard> {
        crate::session_alias_guard::register_session_aliases_with_drop_guard(
            &self.dispatcher,
            &self.session_id,
            &self.local_node_id,
            &self.peer_id,
        )
    }

    /// stage (c): called when a write on the primary transport
    /// returns an I/O error. Advances the per-session consecutive-error
    /// counter and, when the threshold is reached, fires
    /// [`Self::fire_hot_standby_trigger`]. The probe's success depends
    /// on the transport being in a half-dead state at trigger time
    /// (writes refused but reads still OK — common with Windows Firewall
    /// outbound blocks). If the primary is fully dead, the probe's
    /// `HandoffInit` send fails cleanly and the session falls back to
    /// legacy reconnect-with-handshake.
    ///
    /// Slice 29: counter + threshold logic encapsulated in
    /// [`crate::write_error_tracker::WriteErrorTracker`].
    /// This method now just delegates + gives naming for the trigger
    /// reason string.
    fn on_primary_write_error(&self, tracker: &mut crate::write_error_tracker::WriteErrorTracker) {
        use crate::write_error_tracker::TriggerFire;
        if let TriggerFire::Yes = tracker.on_error() {
            let _ = self.fire_hot_standby_trigger("write_error_threshold");
        }
    }

    /// stage (c.2): proactive degradation signal. Fired when
    /// the runner notices it has been RX-stalled for a prolonged fraction
    /// of `idle_timeout` — i.e. peer hasn't sent ANY frame (including
    /// keepalives) for much longer than normal, indicating the primary
    /// transport is likely one-way-broken in both directions.
    ///
    /// Unlike `on_primary_write_error` this fires BEFORE a write actually
    /// fails — so the session is still carrying writes at the moment the
    /// warm-probe's `HandoffInit` goes out. The probe has the full
    /// remaining `1/3 · idle_timeout` window to complete its handshake
    /// before the session's idle timeout would close everything anyway.
    fn on_primary_rx_stall(&self) {
        let _ = self.fire_hot_standby_trigger("rx_stall");
    }

    /// Initiator-side `RekeyAck` frame handler.  Mirror of
    /// `handle_rekey_init_arm` but for the initiator path — we sent a
    /// `RekeyInit`, peer replied with their own ephemeral pubkey, now we
    /// derive new keys and switch ciphers.
    ///
    /// Like the responder helper, stashes the OLD `rx_cipher` into the
    /// shared `rx_cipher_prev` grace ring before swapping to NEW —
    /// without this, in-flight peer frames sealed with peer's OLD tx
    /// (sent BEFORE peer received our RekeyAck) cannot decrypt with our
    /// NEW rx and trigger `session.violation` → ban. The initiator-side
    /// asymmetry that used to exist here surfaced as a stall pattern
    /// under iperf-scale throughput (every byte-threshold-driven rekey
    /// was a race with in-flight frames).
    ///
    /// Returns [`ControlFlow::Break`] to tear the session down when the peer's
    /// rekey ephemeral is non-contributory (a downgrade-toward-known-secret
    /// attempt); [`ControlFlow::Continue`] on every normal path.
    fn handle_rekey_ack_arm(
        &mut self,
        body: &[u8],
        rekey: &mut crate::rekey_context::RekeyContext,
        rx_cipher_prev: &mut crate::rekey_rx_grace_buffer::RekeyRxGraceBuffer,
    ) -> std::ops::ControlFlow<()> {
        use std::ops::ControlFlow;
        // Initiator path: peer confirmed the rekey, sent their pubkey.
        if rekey.is_awaiting_ack()
            && let Ok(payload) = RekeyPayload::decode(body)
        {
            // RTT measurement: tag elapsed since RekeyInit push so
            // operator can observe ack-arrival distribution and
            // verify — does it ever approach 30s grace?
            let init_to_ack_ms = rekey.last_rekey_at().elapsed().as_millis();
            // l: demoted to DEBUG. Aggregate rate visible via
            // `veil_rekey_ack_received_total` counter.
            self.logger.debug(
                "session.rekey.ack.rx",
                format!(
                    "peer_id={} gen={} init_to_ack_ms={}",
                    hex_short(&self.peer_id),
                    rekey.generation(),
                    init_to_ack_ms
                ),
            );
            if let Some(m) = &self.metrics {
                m.inc_rekey_ack_received();
            }
            let Some(keypair) = rekey.take_initiator_keypair() else {
                // FSM invariant violated: state changed between guard and take.
                // Treat as a no-op to avoid panicking the session.
                return ControlFlow::Continue(());
            };
            let shared = match kex::compute_shared_secret(keypair, &payload.ephemeral_pubkey) {
                Ok(s) => s,
                Err(e) => {
                    // Peer's rekey ephemeral was non-contributory — abort
                    // the rekey AND tear the session down: continuing with
                    // the existing keys against a peer that just tried to
                    // negotiate down to a known-secret is unsafe.
                    self.logger.warn(
                        "session.rekey.non_contributory",
                        format!("peer_id={} error={}", hex_short(&self.peer_id), e),
                    );
                    return ControlFlow::Break(());
                }
            };
            let new_keys = session_kdf::derive_rekey_keys(
                &shared,
                &self.session_id,
                &self.local_node_id,
                &self.peer_id,
            );
            // Stash the OLD rx_cipher into the grace ring before swapping.
            // Mirrors the responder-side stash in `handle_rekey_init_arm`.
            // Without this in-flight peer frames sealed with peer's OLD tx
            // (sent BEFORE peer's RekeyAck reached us) cannot decrypt with
            // NEW rx and trigger session.violation under iperf-scale load.
            if let Some(old) = self.crypto.rx_cipher.take() {
                let now = tokio::time::Instant::now();
                let outcome = rx_cipher_prev.push(old, now);
                if outcome.evicted_due_to_capacity {
                    if let Some(m) = &self.metrics {
                        m.inc_rekey_grace_cap_eviction();
                    }
                    self.logger.warn(
                        "session.rekey.grace.cap_evict",
                        format!(
                            "peer_id={} gen={} role=initiator cap={} — back-to-back rekeys outpaced 30s grace",
                            hex_short(&self.peer_id),
                            rekey.generation(),
                            rx_cipher_prev.capacity()
                        ),
                    );
                }
            }
            self.crypto.tx_cipher = Some(SessionCipher::new(&new_keys.tx_key, true));
            self.crypto.rx_cipher = Some(SessionCipher::new(&new_keys.rx_key, true));
            self.session_id = new_keys.session_id;
            rekey.record_rekey_complete(tokio::time::Instant::now());
            // l: demoted to DEBUG.
            self.logger.debug(
                "session.rekey.complete",
                format!(
                    "peer_id={} gen={} role=initiator init_to_ack_ms={} grace_buffer_len={}",
                    hex_short(&self.peer_id),
                    rekey.generation(),
                    init_to_ack_ms,
                    rx_cipher_prev.len()
                ),
            );
        }
        ControlFlow::Continue(())
    }

    /// Handler for incoming `SessionMsg::RekeyKeptInit`. The peer (with
    /// lower node_id) is signaling that they kept their own init and dropped
    /// ours during a mutual-rekey-init collision — our pending init won't
    /// be ACK'd. Reset our state to `Idle` so we stop waiting, and push
    /// `last_rekey_at` to "now" so the time-threshold rekey trigger doesn't
    /// fire immediately again. This breaks the collision-loop pattern that
    /// would otherwise have both sides re-crossing the byte threshold in
    /// lockstep.
    fn handle_rekey_kept_init_arm(&mut self, rekey: &mut crate::rekey_context::RekeyContext) {
        if rekey.is_awaiting_ack() {
            rekey.reset_to_idle();
        }
        rekey.touch_last_rekey_at(tokio::time::Instant::now());
        if let Some(m) = &self.metrics {
            m.inc_rekey_kept_init_received();
        }
        self.logger.info(
            "session.rekey.collision.kept_init.rx",
            format!(
                "peer_id={} gen={} — peer signaled their init wins; resetting to Idle",
                hex_short(&self.peer_id),
                rekey.generation()
            ),
        );
    }

    /// PQ-rekey responder. Peer sent a fresh ML-KEM EK; we update our
    /// cache so future outgoing E2E messages to them are encapsulated
    /// under the new key, then reply with an empty `MlKemRekeyAck`.
    ///
    /// `ControlFlow::Break` is returned on cipher/wire-write failure
    /// (same session-fatal contract as the X25519 rekey path).
    fn handle_mlkem_rekey_ek_arm(
        &mut self,
        body: &[u8],
        wire_tx: &mpsc::Sender<veil_bufpool::PooledShared>,
        write_error_count: &mut crate::write_error_tracker::WriteErrorTracker,
    ) -> std::ops::ControlFlow<()> {
        use std::ops::ControlFlow;

        if let (Ok(payload), Some(cache)) = (
            MlKemRekeyEkPayload::decode(body),
            self.crypto.peer_mlkem_keys.as_ref(),
        ) {
            {
                let mut c = wlock!(cache);
                if c.len() >= veil_proto::budget::MAX_PEER_MLKEM_CACHE
                    && let Some(oldest) = c.iter().min_by_key(|(_, (_, ts))| *ts).map(|(id, _)| *id)
                {
                    c.remove(&oldest);
                }
                c.insert(
                    self.peer_id,
                    (
                        payload.encapsulation_key.to_vec(),
                        std::time::Instant::now(),
                    ),
                );
            }
            // Send MlKemRekeyAck (empty body).
            let mut ack_hdr =
                FrameHeader::new(FrameFamily::Session as u8, SessionMsg::MlKemRekeyAck as u16);
            ack_hdr.body_len = 0;
            let ack_frame = encode_header(&ack_hdr).to_vec();
            let wire_ack = if let Some(cipher) = self.crypto.tx_cipher.as_mut() {
                match apply_tx_cipher(&ack_frame, cipher) {
                    Some(enc) => enc,
                    None => return ControlFlow::Break(()),
                }
            } else {
                veil_bufpool::pooled_shared_from_vec(ack_frame)
            };
            if Self::push_wire(wire_tx, wire_ack, &self.metrics).is_err() {
                self.on_primary_write_error(write_error_count);
                return ControlFlow::Break(());
            }
        }
        ControlFlow::Continue(())
    }

    /// PQ-rekey initiator. Peer acknowledged our new EK; commit the
    /// pending DK seed so the dispatcher can decrypt future E2E
    /// messages encrypted with our new EK. FSM-invariant violations log
    /// a warning and no-op.
    fn handle_mlkem_rekey_ack_arm(
        &mut self,
        mlkem_rekey: &mut crate::mlkem_rekey_context::MlKemRekeyContext,
    ) {
        if mlkem_rekey.is_awaiting_ack()
            && let Some(dk_map) = self.crypto.per_session_mlkem_dk.as_ref()
        {
            let now = tokio::time::Instant::now();
            let Some(dk_seed) = mlkem_rekey.take_dk_seed_on_ack(now) else {
                // FSM invariant violated — state was changed between the
                // is_awaiting_ack check and take_dk_seed_on_ack. This should
                // never happen in a single-threaded session loop, but log
                // a warning so the anomaly is visible in production.
                self.logger.warn(
                    "session.mlkem_rekey_fsm_violation",
                    format!(
                        "peer_id={} MlKemRekeyAck received but state is not AwaitingAck",
                        hex_short(&self.peer_id)
                    ),
                );
                return;
            };
            // cap unbounded HashMap growth. Random
            // eviction is acceptable — a missed dk-cache entry forces the
            // next rekey to perform a full ML-KEM exchange.
            {
                use veil_proto::budget::MAX_PER_SESSION_MLKEM_DK;
                let mut g = lock!(dk_map);
                if g.len() >= MAX_PER_SESSION_MLKEM_DK
                    && !g.contains_key(&self.peer_id)
                    && let Some(k) = g.keys().next().copied()
                {
                    g.remove(&k);
                }
                // Phase 6 slice 6h — wrap the raw dk_seed in mlocked
                // SensitiveBytesN<64> storage before stash.  The source
                // [u8; 64] continues to live on the stack for one more
                // instruction; that stack copy is a brief tail-leak that
                // future slices can close through generate_keypair signature
                // changes (out of scope here).
                g.insert(
                    self.peer_id,
                    veil_util::sensitive_bytes::SensitiveBytesN::<
                        { veil_e2e::DK_SEED_BYTES },
                    >::from_bytes(dk_seed),
                );
            }
        }
    }

    /// Hot-standby `HandoffInit` handler. Peer announces it's about to
    /// swap to a warm transport; we stash the rx_key + nonce keyed on
    /// `(session_id, peer_id)` in the `HandoffRegistry` so that when
    /// the peer's warm socket arrives, we can verify the inbound HMAC
    /// and accept the swap. Then emit a `HandoffAck` on the primary
    /// AEAD session via the priority-queue flush (same pattern as
    /// `RekeyAck`).
    ///
    /// All failure paths (bad payload / no raw_session_keys / no
    /// registry) log a warning or record a violation and no-op back
    /// to the caller's `continue`. No frame is sent directly, so
    /// no session-fatal failure mode.
    fn handle_handoff_init_arm(
        &mut self,
        body: &[u8],
        pq: &mut crate::priority_queue::PriorityQueue,
    ) {
        let init = match veil_proto::session::HandoffInitPayload::decode(body) {
            Ok(p) => p,
            Err(e) => {
                self.record_violation(&format!("bad HandoffInit: {e}"));
                return;
            }
        };
        // We need the receive-side AEAD key to hand to the registry —
        // this is the key that peer-side HMAC will be verifiable against
        // on the warm socket. For the handoff protocol, "rx_key" on
        // this side matches "tx_key" on the peer's side under OVL1 DH.
        let (_tx_key, rx_key, _session_id) = match self.raw_session_keys {
            Some(k) => k,
            None => {
                self.logger.warn(
                    "session.handoff.init.no_keys",
                    format!(
                        "peer_id={} dropping HandoffInit — raw session keys missing",
                        hex_short(&self.peer_id)
                    ),
                );
                return;
            }
        };
        if let Some(reg) = self.hot_standby.handoff_registry.as_ref() {
            reg.insert(self.session_id, self.peer_id.into(), init.nonce, rx_key);
            self.logger.info(
                "session.handoff.init.received",
                format!(
                    "peer_id={} stashed pending handoff",
                    hex_short(&self.peer_id)
                ),
            );
        } else {
            self.logger.warn(
                "session.handoff.init.no_registry",
                format!(
                    "peer_id={} runner has no registry — ignoring HandoffInit",
                    hex_short(&self.peer_id)
                ),
            );
            return;
        }
        // Emit HandoffAck on the priority queue (same flush pattern as
        // RekeyAck) so the initiator knows we are ready.
        let ack_body = veil_proto::session::HandoffAckPayload { nonce: init.nonce }.encode();
        let mut ack_hdr =
            FrameHeader::new(FrameFamily::Session as u8, SessionMsg::HandoffAck as u16);
        ack_hdr.body_len = ack_body.len() as u32;
        let mut ack_frame = encode_header(&ack_hdr).to_vec();
        ack_frame.extend_from_slice(&ack_body);
        pq.push(
            veil_proto::priority::INTERACTIVE,
            veil_bufpool::pooled_shared_from_vec(ack_frame),
        );
    }

    /// b bufpool: decrypt-in-place AEAD decrypt path for a freshly-read frame body.
    ///
    /// Hot path: invokes `cipher.open_in_place(raw_body, &aad)` so the
    /// plaintext is written into the same pooled buffer that held the
    /// ciphertext — eliminates the `Vec::with_capacity(plaintext_len)`
    /// allocation that `cipher.open` would otherwise produce per frame.
    /// `raw_body.len` shrinks by `AEAD_OVERHEAD` (16 B) on success.
    ///
    /// Rekey-grace fallback: when current cipher
    /// fails AND `rx_cipher_prev` is non-empty, the buffer is now
    /// CORRUPTED by the failed in-place attempt — we cannot retry against
    /// the prev ciphers on the same buffer. To preserve correctness, the
    /// caller must hand us a pre-captured snapshot of the original
    /// ciphertext (see `decrypt_frame_body_in_place_with_snapshot`); we
    /// fall back to the heap-allocating [`SessionCipher::open`] on that
    /// snapshot. Snapshot is captured ONLY when prev-ciphers are armed
    /// (~ 30 s post-rekey window) — fast path skips the copy entirely.
    ///
    /// Outcomes:
    /// `Passthrough` — no cipher or empty body; raw_body is the plaintext
    /// `InPlace` — in-place decrypt succeeded; raw_body contains plaintext
    /// `GracePlaintext(Vec)` — fallback to prev cipher; plaintext allocated
    /// separately (rare, only during rekey grace)
    /// `ControlFlow::Break` — nonce overflow or decrypt-failed-without-
    /// grace; caller should tear down the session
    fn decrypt_frame_body_in_place(
        &mut self,
        raw_body: &mut Vec<u8>,
        header_family: u8,
        header_msg_type: u16,
        rekey: &crate::rekey_context::RekeyContext,
        rx_cipher_prev: &mut crate::rekey_rx_grace_buffer::RekeyRxGraceBuffer,
    ) -> std::ops::ControlFlow<(), DecryptInPlaceOutcome> {
        use std::ops::ControlFlow;

        let Some(cipher) = self.crypto.rx_cipher.as_mut() else {
            return ControlFlow::Continue(DecryptInPlaceOutcome::Passthrough);
        };
        // cycle-7 M1: with a cipher present, even a zero-plaintext control frame
        // MUST carry its AEAD tag (sealed by `apply_tx_cipher`). A genuinely
        // empty body here is therefore UNAUTHENTICATED — a pre-M1 peer, or an
        // on-path forgery of Keepalive / RekeyKeptInit / MlKemRekeyAck /
        // Backpressure. Reject it (tear the session down) instead of passing it
        // through unverified. A sealed empty frame is NOT empty here: its body
        // is the 16-byte AEAD tag, so it flows to the open path below.
        if raw_body.is_empty() {
            log::warn!(
                "session.rx: empty-body frame received with cipher active — \
                 rejecting unauthenticated control frame (peer pre-M1 or forged)"
            );
            return ControlFlow::Break(());
        }
        let aad = frame_aad(header_family, header_msg_type);
        let now = tokio::time::Instant::now();
        rx_cipher_prev.prune_expired(now);

        // Conditional snapshot: pay the buffer-copy cost only when rekey-grace
        // is armed (post-rekey 30 s window). Common case: prev_ciphers empty
        // → no snapshot → zero-copy fast path.
        let grace_snapshot = if !rx_cipher_prev.is_empty() {
            Some(raw_body.clone())
        } else {
            None
        };

        match cipher.open_in_place(raw_body, &aad) {
            Ok(()) => ControlFlow::Continue(DecryptInPlaceOutcome::InPlace),
            Err(veil_crypto::session_cipher::CipherError::NonceOverflow) => {
                self.logger.error(
                    "session.nonce_overflow",
                    format!(
                        "rx nonce counter exhausted peer_id={}",
                        hex_short(&self.peer_id)
                    ),
                );
                ControlFlow::Break(())
            }
            Err(_) => {
                let Some(snapshot) = grace_snapshot else {
                    // No grace armed — hard fail. Mirrors the original
                    // decrypt_frame_body error path verbatim.
                    self.logger.warn(
                        "session.decrypt_failed",
                        format!(
                            "peer_id={} gen={} grace_buffer_len=0 since_last_rekey_ms={}",
                            hex_short(&self.peer_id),
                            rekey.generation(),
                            rekey.last_rekey_at().elapsed().as_millis()
                        ),
                    );
                    if let Some(m) = &self.metrics {
                        m.inc_decrypt_failures();
                    }
                    self.record_violation("AEAD decryption failed");
                    return ControlFlow::Break(());
                };
                // Grace armed — try prev ciphers against snapshot (raw_body
                // is corrupted from the failed in-place attempt).
                let prev_match = rx_cipher_prev.try_open(&snapshot, &aad, now);
                match prev_match {
                    Some(hit) => {
                        if let Some(m) = &self.metrics {
                            m.inc_rekey_decrypt_fallback();
                        }
                        // j: demoted to DEBUG. Fallback decrypts
                        // fire ~1/sec under rekey churn; aggregate visibility via
                        // `veil_rekey_decrypt_fallback_total` counter.
                        self.logger.debug(
                            "session.decrypt.fallback",
                            format!(
                                "peer_id={} gen={} prev_slot={} prev_age_ms={} buffer_len={}",
                                hex_short(&self.peer_id),
                                rekey.generation(),
                                hit.slot_from_newest,
                                hit.age_ms,
                                rx_cipher_prev.len()
                            ),
                        );
                        ControlFlow::Continue(DecryptInPlaceOutcome::GracePlaintext(hit.plaintext))
                    }
                    None => {
                        self.logger.warn(
                            "session.decrypt_failed",
                            format!(
                                "peer_id={} gen={} grace_buffer_len={} since_last_rekey_ms={}",
                                hex_short(&self.peer_id),
                                rekey.generation(),
                                rx_cipher_prev.len(),
                                rekey.last_rekey_at().elapsed().as_millis()
                            ),
                        );
                        if let Some(m) = &self.metrics {
                            m.inc_decrypt_failures();
                        }
                        self.record_violation("AEAD decryption failed");
                        ControlFlow::Break(())
                    }
                }
            }
        }
    }

    /// Compute the `await_next_input` sleep deadline for the next
    /// iteration of the runner's main `select!`.  Combines up to seven
    /// independent timer sources:
    ///
    /// * **battery_keepalive** — always: 60s tick for re-sampling battery
    ///   level + mobile-bg-keepalive factor.
    /// * **idle_deadline** — when `timer_enabled` (idle-timeout enabled):
    ///   the cap-time after which we close a silent session.
    /// * **next_keepalive** — when `keepalive_enabled`: the time of our
    ///   next outgoing Keepalive frame.
    /// * **next_cover** — when `cover_enabled`: time
    ///   of our next discardable padding frame.
    /// * **stall_trigger_deadline** — when `idle_enabled` AND the trigger
    ///   hasn't already fired for this stall episode: 2/3 · idle_timeout
    ///   wake-up for the proactive rx-stall trigger.
    /// * **keepalive_probe_deadline** — when a probe is in flight: the
    ///   `pending_keepalive_ack_since + keepalive_probe_timeout` deadline
    ///   for the TX-health check.
    /// * **coalesce_until** — when outbound batching is engaged (
    ///   deferred): time when the batch window expires.
    ///
    /// Pure function on the supplied inputs — no `self` state read.
    /// Lifted out as a free associated fn rather than a method so the
    /// caller can pre-compute the inputs once and feed them in.
    #[allow(clippy::too_many_arguments)] // 7 independent timer sources; structs would obscure the contract
    #[allow(clippy::too_many_arguments)]
    fn compute_sleep_deadline(
        timers: &crate::timers::SessionTimers,
        battery_keepalive: &crate::battery_adjusted_keepalive::BatteryAdjustedKeepalive,
        timer_enabled: bool,
        keepalive_enabled: bool,
        keepalive_probe_trigger_fired: bool,
        keepalive_probe_timeout: std::time::Duration,
        pending_keepalive_ack_since: Option<tokio::time::Instant>,
        stall_trigger_fired: bool,
        coalesce_until: Option<tokio::time::Instant>,
        rotation_deadline: Option<tokio::time::Instant>,
    ) -> Option<tokio::time::Instant> {
        let bat = battery_keepalive.next_check();
        let timer_deadline = if timer_enabled {
            let idle_deadline = timers.idle_deadline();
            let mut kd = if timers.keepalive_enabled() {
                idle_deadline.min(timers.next_keepalive())
            } else {
                idle_deadline
            };
            // Cover-traffic deadline (anti-DPI). Always included when
            // cover_enabled — on fire we emit a Padding frame from the
            // timer branch.
            if timers.cover_enabled() {
                kd = kd.min(timers.next_cover());
            }
            // stage (c.2): wake to catch the rx-stall threshold
            // at 2/3 · idle_timeout. Only matters when we haven't
            // already fired the trigger for this stall episode.
            if timers.idle_enabled() && !stall_trigger_fired {
                kd = kd.min(timers.stall_trigger_deadline());
            }
            // stage (c.2.2): wake at the earliest keepalive-
            // probe timeout so the TX-health check actually fires.
            if keepalive_enabled
                && !keepalive_probe_trigger_fired
                && keepalive_probe_timeout > std::time::Duration::ZERO
                && let Some(t) = pending_keepalive_ack_since
            {
                kd = kd.min(t + keepalive_probe_timeout);
            }
            Some(kd.min(bat))
        } else {
            Some(bat)
        };
        // deferred : fold the coalesce deadline in so
        // the runner emerges from `await_next_input` exactly when the
        // batch window expires. Without this the runner would sit idle
        // (no input, no timer expiry) and deferred frames would only
        // flush when the next external event arrived — defeating the
        // bounded-latency contract.
        let with_coalesce = match (timer_deadline, coalesce_until) {
            (Some(s), Some(c)) => Some(s.min(c)),
            (None, Some(c)) => Some(c),
            (s, None) => s,
        };
        // **Q.7 audit batch**: fold the rotation deadline in too,
        // otherwise the `NextInput::Timer` arm never gets reached
        // in an idle session (keepalive=0, no app traffic) and the deadline
        // never fires.  Production sessions usually have non-zero
        // keepalive so the timer fires regularly, but idle / test
        // configurations need this explicit wake-up to make rotation
        // actually trigger.
        match (with_coalesce, rotation_deadline) {
            (Some(s), Some(r)) => Some(s.min(r)),
            (None, Some(r)) => Some(r),
            (s, None) => s,
        }
    }

    /// X25519 session-rekey threshold check. Fires when the session
    /// is encrypted, has a valid session_id, and no rekey is already
    /// in flight. Triggers (`RekeyTrigger`):
    /// * **byte threshold** — `rekey_bytes_threshold` accumulated TX+RX
    ///   bytes since the last rekey.
    /// * **time threshold** — `rekey_time_threshold_secs` elapsed
    ///   since the last rekey.
    /// * **nonce watermark** — either
    ///   cipher's frame counter approaches 2^64. Logged separately
    ///   so operators can distinguish proactive cipher-counter rekeys
    ///   from the regular byte/time-driven cadence.
    ///
    /// Emits a `SessionMsg::RekeyInit` on the priority queue at
    /// `INTERACTIVE` and transitions `rekey` to `AwaitingAck`.
    fn maybe_initiate_x25519_rekey(
        &mut self,
        rekey: &mut crate::rekey_context::RekeyContext,
        pq: &mut crate::priority_queue::PriorityQueue,
    ) {
        let now = tokio::time::Instant::now();
        // audit cycle-8 H7: if a prior RekeyInit was never answered (peer crash
        // / lost RekeyAck — there is no rekey retransmit), the FSM would sit in
        // AwaitingAck forever, blocking ALL future rekeys including the
        // nonce-exhaustion failsafe (gated on is_idle below). Time it out back to
        // Idle so a fresh init can fire.
        const REKEY_ACK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
        if rekey.awaiting_ack_timed_out(now, REKEY_ACK_TIMEOUT) {
            self.logger.info(
                "session.rekey.ack_timeout",
                format!(
                    "peer_id={} — RekeyAck not received within {}s; resetting to allow re-init",
                    hex_short(&self.peer_id),
                    REKEY_ACK_TIMEOUT.as_secs()
                ),
            );
            rekey.reset_to_idle();
        }
        if !(self.crypto.tx_cipher.is_some() && self.session_id != [0u8; 32] && rekey.is_idle()) {
            return;
        }
        // defence-in-depth — also rekey when the nonce
        // counter approaches 2^64.
        const NONCE_REKEY_WATERMARK: u64 = 1u64 << 62;
        let nonce_pressure = self
            .crypto
            .tx_cipher
            .as_ref()
            .is_some_and(|c| c.frames_processed() >= NONCE_REKEY_WATERMARK)
            || self
                .crypto
                .rx_cipher
                .as_ref()
                .is_some_and(|c| c.frames_processed() >= NONCE_REKEY_WATERMARK);
        let Some(trigger) = rekey.should_initiate_rekey(now, nonce_pressure) else {
            return;
        };
        if matches!(trigger, crate::rekey_context::RekeyTrigger::NonceWatermark) {
            self.logger.info(
                "session.rekey.nonce_watermark",
                format!(
                    "peer_id={} — proactive rekey before nonce exhaustion",
                    hex_short(&self.peer_id)
                ),
            );
        }
        let kp = kex::generate_ephemeral();
        let pubkey = kp.public_key;
        let rekey_body = RekeyPayload {
            ephemeral_pubkey: pubkey,
        }
        .encode();
        let mut rekey_hdr =
            FrameHeader::new(FrameFamily::Session as u8, SessionMsg::RekeyInit as u16);
        rekey_hdr.body_len = rekey_body.len() as u32;
        let mut rekey_frame = encode_header(&rekey_hdr).to_vec();
        rekey_frame.extend_from_slice(&rekey_body);
        let bytes_log = rekey.bytes_since_rekey();
        rekey.enter_awaiting_ack(kp, now);
        pq.push(
            veil_proto::priority::INTERACTIVE,
            veil_bufpool::pooled_shared_from_vec(rekey_frame),
        );
        // 6.33 visibility: log the trigger reason so operators
        // can judge (a) byte vs time vs nonce-pressure mix.
        // l: demoted to DEBUG. `veil_rekey_init_sent_total`.
        self.logger.debug(
            "session.rekey.init.tx",
            format!(
                "peer_id={} gen={} trigger={} bytes_since_rekey={}",
                hex_short(&self.peer_id),
                rekey.generation(),
                trigger.as_log_str(),
                bytes_log
            ),
        );
        if let Some(m) = &self.metrics {
            m.inc_rekey_init_sent();
        }
    }

    /// ML-KEM E2E key rotation threshold check.  Only fires when E2E
    /// key infrastructure is fully wired (`per_session_mlkem_dk` +
    /// `peer_mlkem_keys` both Some) and no rotation is already in flight.
    /// Emits a `SessionMsg::MlKemRekeyEk` carrying the new
    /// encapsulation key and transitions `mlkem_rekey` to `AwaitingAck`.
    /// The peer's `RekeyAck` commit-on-receive path lives in
    /// `handle_mlkem_rekey_ack_arm`.
    fn maybe_initiate_mlkem_rekey(
        &mut self,
        mlkem_rekey: &mut crate::mlkem_rekey_context::MlKemRekeyContext,
        pq: &mut crate::priority_queue::PriorityQueue,
    ) {
        if !(self.crypto.per_session_mlkem_dk.is_some()
            && self.crypto.peer_mlkem_keys.is_some()
            && mlkem_rekey.is_idle()
            && mlkem_rekey.should_initiate_rekey(tokio::time::Instant::now()))
        {
            return;
        }
        let (ek, dk_seed) = veil_e2e::generate_keypair();
        let payload = MlKemRekeyEkPayload {
            encapsulation_key: ek,
        };
        let body = payload.encode();
        let mut hdr = FrameHeader::new(FrameFamily::Session as u8, SessionMsg::MlKemRekeyEk as u16);
        hdr.body_len = body.len() as u32;
        let mut frame = encode_header(&hdr).to_vec();
        frame.extend_from_slice(&body);
        mlkem_rekey.enter_awaiting_ack(dk_seed);
        pq.push(
            veil_proto::priority::INTERACTIVE,
            veil_bufpool::pooled_shared_from_vec(frame),
        );
    }

    /// Drain the per-session outbox channel into the priority queue.
    /// Called at the top of each `select!` iteration; pulls every
    /// queued frame from `outbox.try_recv` until `Empty`.
    ///
    /// Returns `Break` if the channel's `Sender` half has been
    /// dropped (— `SessionTxRegistry::unregister` from
    /// `ban_node` / `kill_session` / session close). The caller
    /// returns from `run` so the `SessionGuard` drops, the TCP
    /// connection FINs cleanly, and banned peers stop receiving frames.
    fn drain_outbox_into_pq(
        &self,
        outbox: &mut mpsc::Receiver<crate::tx_registry::PriorityFrame>,
        pq: &mut crate::priority_queue::PriorityQueue,
    ) -> std::ops::ControlFlow<()> {
        use std::ops::ControlFlow;
        use tokio::sync::mpsc::error::TryRecvError;
        loop {
            match outbox.try_recv() {
                Ok((prio, frame)) => {
                    // chunking is always supported (single protocol version),
                    // so no CHUNK-flag gating is needed here.
                    pq.push(prio, frame);
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    log::info!(
                        "runner: outbox tx dropped — shutting down session to peer {:?}",
                        &self.peer_id[..4],
                    );
                    return ControlFlow::Break(());
                }
            }
        }
        ControlFlow::Continue(())
    }

    /// Drain the per-session RPC outbox into the priority queue,
    /// registering each request's response channel in `pending_responses`
    /// keyed by `request_id`.
    ///
    /// Cap + TTL eviction (`evict_expired` + `evict_oldest_if_at_capacity`)
    /// runs once per inserted request so the response table stays
    /// bounded under sustained RPC traffic. Frame is pushed at
    /// `INTERACTIVE` priority to match the latency expectation of
    /// request-response patterns.
    fn drain_rpc_outbox_into_pq(
        &self,
        rpc_outbox: &mut mpsc::Receiver<crate::outbox::OutboxRequest>,
        pq: &mut crate::priority_queue::PriorityQueue,
        pending_responses: &mut crate::pending_response_table::PendingResponseTable,
    ) {
        while let Ok(req) = rpc_outbox.try_recv() {
            let now = tokio::time::Instant::now();
            pending_responses.evict_expired(now);
            pending_responses.evict_oldest_if_at_capacity();
            pending_responses.insert(req.request_id, req.response_tx, now);
            pq.push(
                veil_proto::priority::INTERACTIVE,
                veil_bufpool::pooled_shared_from_vec(req.frame),
            );
        }
    }

    /// Session-ticket store-on-receive. Server sent us an encrypted
    /// session-resumption ticket; we store the blob alongside our own
    /// session keys so the next reconnect can use the fast-path (blob
    /// → server, keys → restoration).  Caps `peer_tickets` at
    /// `MAX_PEER_TICKETS` to prevent unbounded growth — oldest entry
    /// (`min issued_at`) is evicted on insert when full.
    ///
    /// Silently no-ops if `peer_tickets` store is not configured OR
    /// the body length doesn't match `SESSION_TICKET_ENCRYPTED_SIZE`
    /// OR `raw_session_keys` is not available (we don't have the keys
    /// to pair with the ticket blob).
    fn handle_ticket_arm(&mut self, body: &[u8]) {
        if let (Some(store), Some((tx_key, rx_key, session_id))) =
            (self.peer_tickets.as_ref(), self.raw_session_keys)
            && body.len() == veil_proto::budget::SESSION_TICKET_ENCRYPTED_SIZE
        {
            let entry = veil_proto::session::ClientTicketEntry {
                blob: body.to_vec(),
                tx_key,
                rx_key,
                session_id,
                peer_public_key: self.peer_public_key.clone().unwrap_or_default(),
                peer_nonce: self.peer_nonce.clone().unwrap_or_default(),
                issued_at: std::time::Instant::now(),
            };
            let mut tickets = lock!(store);
            // cap peer_tickets at MAX_PEER_TICKETS to prevent
            // unbounded growth on long-running nodes. Evict the oldest
            // entry (min issued_at) when the map is full.
            if tickets.len() >= veil_proto::budget::MAX_PEER_TICKETS
                && let Some(oldest_id) = tickets
                    .iter()
                    .min_by_key(|(_, e)| e.issued_at)
                    .map(|(id, _)| *id)
            {
                tickets.remove(&oldest_id);
            }
            tickets.insert(self.peer_id, entry);
            log::info!(
                "resume.ticket.armed peer={} count={} — stored resume ticket from server",
                veil_util::hex_short(&self.peer_id),
                tickets.len(),
            );
        }
    }

    /// `TransportMigrationNotify` receiver-side handler.  Peer is
    /// announcing they've bound a new listener URI (ephemeral-port
    /// rotation, Phase 5b/5e) and want us to update our cache so future
    /// reconnects dial the new address.
    ///
    /// Path:
    /// 1. Decode the body.  Malformed → record violation, drop.
    /// 2. Sig-verify against the peer's handshake-attested pubkey.
    ///    The peer_id self-binding (`node_id == BLAKE3(pubkey)`) is
    ///    re-checked inside `verify_transport_migration_notify`; both
    ///    must hold for the new URI to displace the cached one.
    /// 3. Reject IF the announced `node_id` doesn't match our session's
    ///    `peer_id` — a valid sig for ANOTHER node is not authorization
    ///    to update this peer's cache entry.
    /// 4. Insert `(peer_id, new_transport)` into the DHT transport-cache.
    ///    Subsequent `ResolveTransport` lookups skip the round-trip and
    ///    return the announced URI directly.
    /// 5. Replay-window failures (issued_at skew > 5 min) silently drop
    ///    with a debug-level log — old captures replayed long after the
    ///    fact must not displace a live entry, but recording them as
    ///    abuse violations would surface false positives on clock-skewed
    ///    peers.
    pub fn handle_transport_migration_notify_arm(&mut self, body: &[u8]) {
        use veil_proto::session::{
            TransportMigrationNotifyPayload, verify_transport_migration_notify,
        };
        let payload = match TransportMigrationNotifyPayload::decode(body) {
            Ok(p) => p,
            Err(e) => {
                self.record_violation(&format!("bad TransportMigrationNotify: {e}"));
                return;
            }
        };

        // Announced node_id MUST match the session's peer_id.  Without
        // this check, a compromised-but-not-pwned peer could forward
        // someone else's signed notify to poison our cache for a third
        // party.  Self-only sender, no relay semantics.
        if payload.node_id != self.peer_id {
            self.record_violation("TransportMigrationNotify: node_id != session peer_id");
            return;
        }

        // Recover the peer's Ed25519 pubkey from the handshake-stored
        // base64 string.  `peer_public_key` is `None` for server-role
        // sessions where the handshake didn't carry a full pubkey
        // (older protocol versions); in that case there's nothing to
        // verify against, drop silently.
        let pubkey_b64 = match self.peer_public_key.as_ref() {
            Some(s) => s,
            None => {
                self.logger.debug(
                    "session.migration.notify.no_pubkey",
                    format!(
                        "peer_id={} skip (handshake carried no pubkey)",
                        hex_short(&self.peer_id),
                    ),
                );
                return;
            }
        };
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let pubkey_bytes = match STANDARD.decode(pubkey_b64.as_bytes()) {
            Ok(b) if b.len() == 32 => b,
            Ok(b) => {
                self.record_violation(&format!(
                    "TransportMigrationNotify: peer_pubkey len={} (need 32)",
                    b.len(),
                ));
                return;
            }
            Err(e) => {
                self.record_violation(&format!(
                    "TransportMigrationNotify: peer_pubkey base64: {e}",
                ));
                return;
            }
        };
        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(&pubkey_bytes);

        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        if let Err(e) = verify_transport_migration_notify(&payload, &pubkey, now_unix) {
            // Replay-window failures are expected on clock-skewed peers
            // and shouldn't poison the violation tracker.  Treat ANY
            // verify failure as debug-only — a forged sig from a
            // genuinely hostile peer would still be caught by the
            // node_id self-binding above (since the attacker can't
            // produce a valid sig under the real peer's key).
            self.logger.debug(
                "session.migration.notify.verify_failed",
                format!("peer_id={} reason={e}", hex_short(&self.peer_id),),
            );
            return;
        }

        // Push the new URI into the cache.  `insert` overwrites any
        // older entry under the same node_id and refreshes the TTL clock
        // — exactly what we want after a deliberate migration.
        {
            let cache = self.dispatcher.dht().transport_cache();
            let mut c = lock!(cache);
            c.insert(self.peer_id, payload.new_transport.clone());
        }
        self.logger.info(
            "session.migration.notify.applied",
            format!(
                "peer_id={} new_transport={} new_expiry_unix={}",
                hex_short(&self.peer_id),
                payload.new_transport,
                payload.new_expiry_unix,
            ),
        );
    }

    /// PoW-Gated Rendezvous request handler — Slice 5b of the epic.
    /// Spawns a task that runs the controller's full 10-step
    /// orchestration (decode → verify → rate-limit → concurrent-slot
    /// → bind → sign-response).  On `Granted`, builds the
    /// `SessionMsg::EphemeralEndpointResponse` frame and pushes it back
    /// to the same peer through `session_tx_registry.send_to`.  On
    /// `Rejected`, silently drops (DoS-resistance — a bare rejection
    /// would still cost a CPU + bandwidth response).
    ///
    /// **Weak-upgrade pattern:** the dispatcher's strong Arc to the
    /// controller is replaced by a Weak ref so the
    /// `dispatcher → controller → binder → SessionRuntimeContext →
    /// dispatcher` strong-ref cycle doesn't leak on reload.  Each
    /// dispatch upgrades the Weak; if the strong Arc is gone (no
    /// stealth listener configured OR runtime shutting down), the
    /// dispatch silently drops.
    fn handle_rendezvous_request_arm(&self, body: &[u8]) {
        // Upgrade Weak → Arc.  If None, no stealth listener configured;
        // drop silently — DoS-resistant default.
        let controller = {
            let rdv = self.dispatcher.rendezvous_weak();
            let lock = match rdv.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            match lock.as_ref().and_then(|w| w.upgrade()) {
                Some(c) => c,
                None => {
                    self.logger.debug(
                        "rendezvous.request.no_controller",
                        format!(
                            "peer_id={} dropped (stealth listener not configured)",
                            hex_short(&self.peer_id),
                        ),
                    );
                    return;
                }
            }
        };

        // Hand the body to a task — handle_request is async (binder
        // does the actual bind).  Capture peer_id + session_tx_registry
        // ref for shipping the response back.
        let body_vec = body.to_vec();
        let session_tx = self.dispatcher.session_tx_registry();
        let peer_id = self.peer_id;
        let logger = Arc::clone(&self.logger);
        tokio::spawn(async move {
            use crate::rendezvous::{RejectReason, RequestOutcome};
            use veil_proto::{
                codec::encode_header,
                family::{FrameFamily, SessionMsg},
                header::{FrameHeader, HEADER_SIZE},
            };
            match controller.handle_request(&body_vec).await {
                RequestOutcome::Granted {
                    response_bytes,
                    port,
                    ..
                } => {
                    // Build SessionMsg::EphemeralEndpointResponse frame
                    // and push back on the same session.
                    let mut hdr = FrameHeader::new(
                        FrameFamily::Session as u8,
                        SessionMsg::EphemeralEndpointResponse as u16,
                    );
                    hdr.body_len = response_bytes.len() as u32;
                    let mut frame = Vec::with_capacity(HEADER_SIZE + response_bytes.len());
                    frame.extend_from_slice(&encode_header(&hdr));
                    frame.extend_from_slice(&response_bytes);
                    let Some(reg_arc) = session_tx else {
                        logger.warn(
                            "rendezvous.response.no_tx_registry",
                            format!(
                                "peer_id={} granted port={port} but session_tx_registry missing",
                                hex_short(&peer_id),
                            ),
                        );
                        return;
                    };
                    let reg = match reg_arc.read() {
                        Ok(g) => g,
                        Err(poisoned) => poisoned.into_inner(),
                    };
                    // INTERACTIVE priority (matches DetachPayload / migration
                    // notify pattern).  send_to(peer_id, priority, bytes)
                    // returns true on enqueue success.
                    const INTERACTIVE: u8 = 1;
                    let ok = reg.send_to(&peer_id, INTERACTIVE, frame);
                    if ok {
                        logger.info(
                            "rendezvous.response.sent",
                            format!("peer_id={} new_port={port}", hex_short(&peer_id),),
                        );
                    } else {
                        logger.warn(
                            "rendezvous.response.send_failed",
                            format!(
                                "peer_id={} send_to returned false (queue full or peer gone)",
                                hex_short(&peer_id),
                            ),
                        );
                    }
                }
                RequestOutcome::Rejected(reason) => {
                    // Don't ship a rejection wire frame — DoS-resistance.
                    // Logging only.
                    let kind = match reason {
                        RejectReason::Decode(_) => "decode",
                        RejectReason::Verify(_) => "verify",
                        RejectReason::NotOurTarget => "not_our_target",
                        RejectReason::RateLimited => "rate_limited",
                        RejectReason::ConcurrencyExhausted => "concurrency_exhausted",
                        RejectReason::BindFailed(_) => "bind_failed",
                    };
                    logger.info(
                        "rendezvous.request.rejected",
                        format!("peer_id={} reason={kind}", hex_short(&peer_id),),
                    );
                }
            }
        });
    }

    /// `HandoffAck` receiver-side forwarder.  Initiator was waiting
    /// for a ready-to-swap signal from the peer; we received it, forward
    /// the nonce to the initiator's one-shot channel (registered in
    /// `handoff_ack_waiters` keyed by `session_id`).
    ///
    /// Missing-waiter case is silently logged at debug — the peer's
    /// pending handoff is already stashed, so any initiator
    /// retry will time out cleanly via the registry's TTL. Bad-payload
    /// path records a violation and no-ops.
    fn handle_handoff_ack_arm(&mut self, body: &[u8]) {
        let ack = match veil_proto::session::HandoffAckPayload::decode(body) {
            Ok(p) => p,
            Err(e) => {
                self.record_violation(&format!("bad HandoffAck: {e}"));
                return;
            }
        };
        let delivered = self
            .hot_standby
            .handoff_ack_waiters
            .as_ref()
            .and_then(|w| w.get(&self.session_id))
            .map(|tx| tx.try_send(ack.nonce).is_ok())
            .unwrap_or(false);
        if delivered {
            self.logger.debug(
                "session.handoff.ack.forwarded",
                format!(
                    "peer_id={} nonce delivered to initiator",
                    hex_short(&self.peer_id)
                ),
            );
        } else {
            self.logger.debug(
                "session.handoff.ack.no_listener",
                format!(
                    "peer_id={} HandoffAck arrived with no waiter",
                    hex_short(&self.peer_id)
                ),
            );
        }
    }

    /// Responder-side `RekeyInit` frame handler.  Performs cipher
    /// manipulation + collision resolution + grace-buffer stashing.
    ///
    /// The **mutual-rekey-init collision resolver** matters: if both
    /// peers crossed the byte-threshold within RTT and each side
    /// simultaneously sent `RekeyInit` while still `AwaitingAck`,
    /// lexicographic node_id ordering chooses a single initiator
    /// (lower id wins).  Without this every collision ended in
    /// terminal AEAD-decrypt failure → session.violation → teardown.
    ///
    /// Returns:
    ///
    /// * `Continue` — caller should `continue` to the next select-loop iteration.
    /// * `Break` — caller should `return` from `run` (cipher /
    ///   wire-write error — session is unrecoverable).
    fn handle_rekey_init_arm(
        &mut self,
        body: &[u8],
        rekey: &mut crate::rekey_context::RekeyContext,
        rx_cipher_prev: &mut crate::rekey_rx_grace_buffer::RekeyRxGraceBuffer,
        wire_tx: &mpsc::Sender<veil_bufpool::PooledShared>,
        write_error_count: &mut crate::write_error_tracker::WriteErrorTracker,
    ) -> std::ops::ControlFlow<()> {
        use std::ops::ControlFlow;

        // Responder path: peer sent us their new ephemeral pubkey.
        if self.crypto.tx_cipher.is_some()
            && self.crypto.rx_cipher.is_some()
            && let Ok(payload) = RekeyPayload::decode(body)
        {
            // l: demoted to DEBUG. `veil_rekey_init_received_total`.
            self.logger.debug(
                "session.rekey.init.rx",
                format!(
                    "peer_id={} gen={}",
                    hex_short(&self.peer_id),
                    rekey.generation()
                ),
            );
            if let Some(m) = &self.metrics {
                m.inc_rekey_init_received();
            }
            // Mutual rekey-init collision resolver — see method docstring
            // for the full incident write-up. Both peers run the same
            // comparison; lower lexicographic node_id keeps its initiator
            // role and drops the peer's init, higher node_id aborts own
            // init and falls through to the responder path below.
            if rekey.is_awaiting_ack() {
                if self.local_node_id < self.peer_id {
                    self.logger.info(
                        "session.rekey.collision.kept_init",
                        format!("peer_id={} gen={} local_node_id<peer_id — keeping own init, dropping peer's",
                            hex_short(&self.peer_id), rekey.generation()),
                    );
                    // Inform the peer that their init has been dropped and
                    // ours is the authoritative one. Without this signal
                    // peer's FSM is still in AwaitingAck (own init pending
                    // ACK that will never come) and under high-throughput
                    // both sides re-cross the byte threshold near-simul and
                    // collide again — leading to the rekey-storm pattern.
                    let kept_init_hdr = FrameHeader::new(
                        FrameFamily::Session as u8,
                        SessionMsg::RekeyKeptInit as u16,
                    );
                    let kept_init_frame = encode_header(&kept_init_hdr).to_vec();
                    // empty body, but `apply_tx_cipher` AEAD-seals it (cycle-7
                    // M1) so the empty frame still proves session-membership to
                    // the peer — the receiver tears down on an unauthenticated
                    // empty frame.
                    let wire_kept_init = {
                        let Some(cipher) = self.crypto.tx_cipher.as_mut() else {
                            return ControlFlow::Continue(());
                        };
                        match apply_tx_cipher(&kept_init_frame, cipher) {
                            Some(enc) => enc,
                            None => return ControlFlow::Continue(()),
                        }
                    };
                    if Self::push_wire(wire_tx, wire_kept_init, &self.metrics).is_err() {
                        self.on_primary_write_error(write_error_count);
                        return ControlFlow::Break(());
                    }
                    if let Some(m) = &self.metrics {
                        m.inc_rekey_kept_init_sent();
                    }
                    return ControlFlow::Continue(());
                }
                self.logger.info(
                    "session.rekey.collision.aborted_init",
                    format!("peer_id={} gen={} local_node_id>peer_id — aborting own init, accepting peer's",
                        hex_short(&self.peer_id), rekey.generation()),
                );
                rekey.reset_to_idle();
            }
            let our_kp = kex::generate_ephemeral();
            let our_pubkey = our_kp.public_key;
            let shared = match kex::compute_shared_secret(our_kp, &payload.ephemeral_pubkey) {
                Ok(s) => s,
                Err(e) => {
                    // Peer's rekey ephemeral was non-contributory — abort the
                    // rekey AND tear the session down (consistent with the
                    // initiator path): a peer negotiating toward a known secret
                    // is treated as a terminal violation, not silently ignored.
                    self.logger.warn(
                        "session.rekey.non_contributory",
                        format!("peer_id={} error={}", hex_short(&self.peer_id), e),
                    );
                    return std::ops::ControlFlow::Break(());
                }
            };
            let new_keys = session_kdf::derive_rekey_keys(
                &shared,
                &self.session_id,
                &self.local_node_id,
                &self.peer_id,
            );

            // Build RekeyAck and encrypt with the OLD tx_cipher, then
            // write directly to the stream to guarantee ordering.
            let ack_body = RekeyPayload {
                ephemeral_pubkey: our_pubkey,
            }
            .encode();
            let mut ack_hdr =
                FrameHeader::new(FrameFamily::Session as u8, SessionMsg::RekeyAck as u16);
            ack_hdr.body_len = ack_body.len() as u32;
            let mut ack_frame = encode_header(&ack_hdr).to_vec();
            ack_frame.extend_from_slice(&ack_body);

            let wire_ack = {
                let Some(cipher) = self.crypto.tx_cipher.as_mut() else {
                    return ControlFlow::Break(());
                };
                match apply_tx_cipher(&ack_frame, cipher) {
                    Some(enc) => enc,
                    None => return ControlFlow::Break(()),
                }
            };
            if Self::push_wire(wire_tx, wire_ack, &self.metrics).is_err() {
                self.on_primary_write_error(write_error_count);
                return ControlFlow::Break(());
            }
            // l: demoted to DEBUG. `veil_rekey_ack_sent_total`.
            self.logger.debug(
                "session.rekey.ack.tx",
                format!(
                    "peer_id={} gen={}",
                    hex_short(&self.peer_id),
                    rekey.generation()
                ),
            );
            if let Some(m) = &self.metrics {
                m.inc_rekey_ack_sent();
            }

            // 6.47-stash the OLD rx cipher as a
            // fallback for in-flight frames the initiator sent BEFORE it
            // received our RekeyAck (those are still encrypted with OLD
            // tx). Without this, the cluster develops transient decrypt-
            // failure storms at every rekey. Cap is `REKEY_RX_PREV_CAP`
            // (3) — back-to-back rekeys don't orphan gen-N-2 within the
            // 30s grace window.
            if let Some(old) = self.crypto.rx_cipher.take() {
                let now = tokio::time::Instant::now();
                let outcome = rx_cipher_prev.push(old, now);
                if outcome.evicted_due_to_capacity {
                    if let Some(m) = &self.metrics {
                        m.inc_rekey_grace_cap_eviction();
                    }
                    self.logger.warn(
                        "session.rekey.grace.cap_evict",
                        format!(
                            "peer_id={} gen={} cap={} — back-to-back rekeys outpaced 30s grace",
                            hex_short(&self.peer_id),
                            rekey.generation(),
                            rx_cipher_prev.capacity()
                        ),
                    );
                }
            }
            // Switch both ciphers to new keys.
            self.crypto.tx_cipher = Some(SessionCipher::new(&new_keys.tx_key, true));
            self.crypto.rx_cipher = Some(SessionCipher::new(&new_keys.rx_key, true));
            self.session_id = new_keys.session_id;
            rekey.record_rekey_complete(tokio::time::Instant::now());
            // l: demoted to DEBUG.
            self.logger.debug(
                "session.rekey.complete",
                format!(
                    "peer_id={} gen={} role=responder grace_buffer_len={}",
                    hex_short(&self.peer_id),
                    rekey.generation(),
                    rx_cipher_prev.len()
                ),
            );
        }
        ControlFlow::Continue(())
    }

    /// Centralised trigger dispatch. Both `on_primary_write_error` and
    /// `on_primary_rx_stall` funnel through here so the controller sees
    /// a single call-site pattern and flap-damping is applied once per
    /// degradation event regardless of which signal raised it.
    ///
    /// Returns `true` iff a warm-probe task was spawned (controller is
    /// configured, `alt_uri` known, flap damping accepted).  Returns
    /// `false` for any "fire-and-forget would no-op" case — caller can
    /// use this signal to teardown the session, since the primary is
    /// known-degraded and no failover is possible (audit batch 2026-05-24
    /// M5: testnet hosts run without an `alt_uri` configured, so the
    /// `keepalive_probe_timeout` trigger fires once but `try_auto_trigger`
    /// returns `false`, the `OnceTrigger` prevents re-firing, and the
    /// session zombies forever — every `outbound_connector` reconnect
    /// collides with the stale `session_tx_registry` entry → permanent split).
    #[must_use]
    fn fire_hot_standby_trigger(&self, reason: &str) -> bool {
        let Some(ctrl) = self.hot_standby.controller.as_ref() else {
            return false;
        };
        // Honor the `[hot_standby] enabled` master switch and skip the
        // futile auto-swap on terminal-close reasons — see
        // `hot_standby_should_auto_fire`.
        if !hot_standby_should_auto_fire(ctrl.enabled(), reason) {
            return false;
        }
        let Some((tx_key, _, _)) = self.raw_session_keys else {
            return false;
        };
        self.logger.info(
            "session.hot_standby.trigger_raised",
            format!("peer_id={} reason={reason}", hex_short(&self.peer_id)),
        );
        // **Q.7 audit batch**: `rotation_deadline` is the only failure-
        // type reason that genuinely benefits from same-URI fallback —
        // the wire is still healthy, we just want fresh TCP+TLS bytes
        // on the line.  All other reasons (`write_error_threshold`,
        // `rx_stall`, `keepalive_probe_timeout`, `writer_closed`)
        // indicate the primary IS degraded, so same-
        // URI would just hit the same problem — keep them on the
        // alt_uri-only path to avoid wasted dials.
        if reason == "rotation_deadline"
            && let Some(primary_uri) = self.primary_uri.as_deref()
        {
            return ctrl.try_rotation_trigger(
                self.peer_id.into(),
                primary_uri,
                self.session_id,
                tx_key,
            );
        }
        // Fallback path for:
        //   * non-rotation reasons (`write_error_threshold`, `rx_stall`,
        //     `keepalive_probe_timeout`, `writer_closed`) — primary is
        //     degraded, only alt_uri makes sense.
        //   * rotation reason without primary_uri (inbound-accepted session).
        //     Server side doesn't initiate rotation in practice, but this
        //     branch keeps the safety property.
        ctrl.try_auto_trigger(self.peer_id.into(), self.session_id, tx_key)
    }

    // ── hot-standby handover ────────────────────────────────────────

    /// Attach a swap-inbox to this runner and return the sender. The
    /// controller task (warm-probe / trigger logic — b/c) pushes
    /// a replacement [`BoxIoStream`] into the sender; the runner's
    /// `run` loop picks it up at the next `await_next_input` tick and
    /// atomically replaces `self.stream` without touching the AEAD
    /// ciphers, `session_id`, or any other per-session state.
    ///
    /// Capacity 1 — only the most-recent pending swap matters; if a
    /// second warm transport becomes ready before the first is picked
    /// up, the controller can `try_send` again after a swap completes.
    ///
    /// Production caller: `register_swap_channel` (below) wraps this
    /// to also publish the sender into the runtime's `SessionSwapRegistry`
    /// so the accept-side `peek_and_dispatch` can route a HandoffAttach
    /// frame into the runner.
    pub fn with_swap_inbox(&mut self) -> mpsc::Sender<BoxIoStream> {
        let (tx, rx) = mpsc::channel(1);
        self.hot_standby.swap_rx = Some(rx);
        tx
    }

    /// stage (d) Task 4a: install a `swap_rx` on this runner and
    /// register the matching sender in `swap_registry` keyed by
    /// `session_id`. Returns a [`SwapRegistryGuard`] whose drop removes
    /// the entry — callers must hold the guard for the lifetime of the
    /// runner (typically by moving it into the task that runs
    /// `SessionRunner::run`).
    ///
    /// A session with `session_id == [0u8; 32]` (no OVL1 handshake yet
    /// e.g. bootstrap-only short-lived sessions) skips registration; the
    /// runner still gets a `swap_rx` but no accept-side path can reach it.
    pub fn register_swap_channel(
        &mut self,
        registry: &std::sync::Arc<crate::handoff::SessionSwapRegistry>,
    ) -> Option<crate::handoff::SwapRegistryGuard> {
        if self.session_id == [0u8; 32] {
            return None;
        }
        // B5: the swap registry also stashes the session's
        // TX key so the admin-driven warm probe can seal HandoffAttach
        // without another lookup. Sessions whose handshake path did
        // not populate `raw_session_keys` (pre-OVL1 sessions in tests)
        // register with an all-zero key — harmless because the probe
        // would still fail earlier at session_id lookup.
        let tx_key = self
            .raw_session_keys
            .map(|(t, _, _)| t)
            .unwrap_or([0u8; 32]);
        let tx = self.with_swap_inbox();
        Some(registry.register(self.session_id, self.peer_id.into(), tx, tx_key))
    }
}

/// Encrypt `frame` in-place using `cipher`.
///
/// Returns `Some(encrypted_frame)` on success, `None` on any cipher or
/// header-decode error. The caller decides the error action (`return` or
/// `break`) based on its loop context.
// ── mobile background-mode keepalive scaling ─────────────────
//
// Global signals (node-wide; one runtime per process) so all session
// runners pick them up without threading new fields through 22+
// construction sites. Toggled atomically by:
// * runtime startup / reload — sets MULTIPLIER from config.mobile.
// background_keepalive_multiplier.
// * AdminCommand::SetMobileBackgroundMode — flips MODE on / off
// in response to the GUI wrapper's onPause / onResume hook.
//
// Composes multiplicatively with the existing battery scaling
// — a backgrounded + low-battery session sees both
// factors. Hard-clamped at MAX so misconfig can't push keepalive
// past idle_timeout.
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering};

/// Global TLS-bucket-padding flag (Phase E23, 2026-05-22).  When `true`,
/// `coalesce_with_padding` pads each outbound frame to the nearest bucket
/// in `TLS_BUCKET_SIZES` ([1300, 4096, 16384]) — DPI hardening: TLS
/// records look like generic HTTPS traffic.  When `false`, frames go
/// out at their natural encrypted size without padding overhead.
///
/// Default **OFF** (changed from previous unconditional ON).  Testnet
/// iperf through ogate revealed unconditional padding inflated single-
/// stream wire traffic ~2.5× (1612 B → 4096 B bucket) and pinned the
/// veil daemon at 70 % single-thread CPU around ~110 Mbps even
/// though all explicit drop counters read ZERO.
///
/// Operators in adversarial-DPI environments flip this via
/// [`set_padding_enabled`] before the session-runner starts;
/// runtime config-wiring (`PaddingPolicy.mode = Adaptive|Full`)
/// belongs to a follow-up commit.
static PADDING_ENABLED: AtomicBool = AtomicBool::new(false);

/// Toggle TLS-bucket frame padding on the outbound hot path.
pub fn set_padding_enabled(on: bool) {
    PADDING_ENABLED.store(on, Ordering::Relaxed);
}

/// `true` if TLS-bucket frame padding is currently enabled.  Surfaced
/// for diagnostic / admin-debug commands.
pub fn padding_enabled() -> bool {
    PADDING_ENABLED.load(Ordering::Relaxed)
}
/// Mobile lifecycle tier:
/// 0 = Foreground (UI active, normal cadence)
/// 1 = Active (background but UI alive — 2× longer keepalive)
/// 2 = LowPower (Doze / iOS BackgroundTask — full multiplier + route-probe paused)
/// Mirrors `veil_proto::MobileBackgroundMode` wire enum byte.
static MOBILE_BACKGROUND_TIER: AtomicU8 = AtomicU8::new(0);
static MOBILE_BACKGROUND_KEEPALIVE_MULTIPLIER: AtomicU32 = AtomicU32::new(1);

/// connection-rotation **maximum** lifetime (seconds). `0` means
/// rotation disabled (sessions live indefinitely subject only to
/// idle_timeout). Set from `cfg.transport.rotation.max_lifetime_secs`
/// (or legacy `cfg.session.max_age_secs`) at runtime startup + reload.
/// Same global-static pattern as the mobile background-mode signals
/// above — avoids threading a new field through 22+ SessionRunner
/// construction sites.
///
/// Paired with [`SESSION_MIN_AGE_SECS`] for range-based sampling.  When
/// rotation is enabled, each session draws a deadline uniformly from
/// the `[min, max]` window — see [`crate::rotation_deadline`] for why
/// a range (not a point with ±10 %) prevents per-fleet rotation-cadence
/// fingerprinting.
static SESSION_MAX_AGE_SECS: AtomicU64 = AtomicU64::new(0);

/// connection-rotation **minimum** lifetime (seconds). Paired with
/// [`SESSION_MAX_AGE_SECS`].  When `0`, the rotation-deadline computer
/// falls back to the legacy `±10 %` jitter around `SESSION_MAX_AGE_SECS`.
/// Set from `cfg.transport.rotation.min_lifetime_secs` at runtime
/// startup + reload.
///
/// Invariant maintained by the setter: if both are non-zero, `min ≤ max`.
static SESSION_MIN_AGE_SECS: AtomicU64 = AtomicU64::new(0);

/// Hard floor on session rotation interval — defends against
/// misconfig / malicious config push that would force rapid
/// reconnect storms. Mirrors the validation rule so even a
/// runtime call bypassing config-validate cannot push below.
pub const MIN_SESSION_MAX_AGE_SECS: u64 = 60;

/// Maximum allowed background multiplier. Mirror of
/// `MobileConfig::MAX_BACKGROUND_KEEPALIVE_MULTIPLIER` — kept here
/// as a hard clamp on the runtime side so even a runtime call
/// bypassing config validation cannot push past the ceiling.
pub const MAX_MOBILE_BACKGROUND_KEEPALIVE_MULTIPLIER: u32 = 120;

/// Hardcoded per-tier multiplier for the `Active` tier:
/// background-but-UI-alive sessions get 2× longer keepalive — modest
/// power savings without committing to the more aggressive LowPower
/// stretch (the user can switch back to foreground at any second).
pub const MOBILE_ACTIVE_TIER_MULTIPLIER: u32 = 2;

/// Set the mobile background-mode tier. Values:
/// `0` = Foreground (no scaling)
/// `1` = Active (2× keepalive)
/// `2` = LowPower (full configured multiplier + route-probe pause)
/// Out-of-range values clamp to `2` (most-conservative tier — fail
/// safely toward stretching keepalive rather than tight cadence).
pub fn set_mobile_background_tier(tier: u8) {
    let clamped = tier.min(2);
    MOBILE_BACKGROUND_TIER.store(clamped, Ordering::Relaxed);
}

/// Legacy bool API — preserved for admin-command callers.
/// Maps `false` → Foreground (tier 0), `true` → LowPower (tier 2).
/// New code should use [`set_mobile_background_tier`] directly to access
/// the Active middle tier.
pub fn set_mobile_background_mode(enabled: bool) {
    set_mobile_background_tier(if enabled { 2 } else { 0 });
}

/// Set the mobile background-mode keepalive multiplier.
/// Clamps to `[1, MAX_MOBILE_BACKGROUND_KEEPALIVE_MULTIPLIER]`.
/// Called from runtime startup / reload with the value from
/// `cfg.mobile.background_keepalive_multiplier`. Used for the
/// LowPower tier; Active tier is hardcoded at
/// `MOBILE_ACTIVE_TIER_MULTIPLIER`.
pub fn set_mobile_background_keepalive_multiplier(multiplier: u32) {
    let clamped = multiplier.clamp(1, MAX_MOBILE_BACKGROUND_KEEPALIVE_MULTIPLIER);
    MOBILE_BACKGROUND_KEEPALIVE_MULTIPLIER.store(clamped, Ordering::Relaxed);
}

/// Read the current mobile background-mode tier.
/// Exposed for diagnostic snapshots
/// and tests. Production callers use this via `mobile_status_provider.rs`
/// to populate the IPC payload's `background_tier` byte.
pub fn current_mobile_background_tier() -> u8 {
    MOBILE_BACKGROUND_TIER.load(Ordering::Relaxed)
}

/// Resolved factor to apply to the keepalive interval right now.
/// Returns 1 (no scaling) when the feature is disabled (multiplier=1)
/// or when the tier is Foreground. Otherwise scales per tier:
/// * Active (tier 1) → `MOBILE_ACTIVE_TIER_MULTIPLIER` (= 2)
/// * LowPower (tier 2) → full configured multiplier
pub fn current_mobile_background_keepalive_factor() -> u32 {
    let multiplier = MOBILE_BACKGROUND_KEEPALIVE_MULTIPLIER.load(Ordering::Relaxed);
    if multiplier <= 1 {
        // Feature disabled — return 1× regardless of tier so default
        // (non-mobile) deployments never see scaling.
        return 1;
    }
    match MOBILE_BACKGROUND_TIER.load(Ordering::Relaxed) {
        0 => 1,
        1 => MOBILE_ACTIVE_TIER_MULTIPLIER,
        _ => multiplier,
    }
}

/// Whether the current tier should suppress non-essential background
/// work (route probes, PEX walks, DHT republish). True only on
/// `LowPower` — `Active` keeps maintenance running at stretched
/// keepalive cadence so the routing table stays warm.
pub fn should_suppress_background_maintenance() -> bool {
    MOBILE_BACKGROUND_TIER.load(Ordering::Relaxed) == 2
}

/// Read the configured background-keepalive multiplier.
/// Exposed for the diagnostic snapshot via `GetMobileStatus` IPC.
pub fn current_mobile_background_keepalive_multiplier() -> u32 {
    MOBILE_BACKGROUND_KEEPALIVE_MULTIPLIER.load(Ordering::Relaxed)
}

// ── deferred : outbound-frame batching ──────────────
//
// Cellular radio wakes once per TCP write. When battery is at-or-below
// `[mobile].low_battery_threshold_pct` and `[mobile].outbound_batch_window_ms`
// is set, the session runner defers the priority-queue drain pass while
// the queue head priority is BULK or BACKGROUND, up to `window_ms`
// since the previous flush. INTERACTIVE / REALTIME frames bypass the
// delay: they sit at queue head thanks to WRR ordering, so peek returns
// them and drain proceeds immediately.
//
// Two signals (battery threshold + window) are stored as process-global
// atomics — same pattern as `MOBILE_BACKGROUND_KEEPALIVE_MULTIPLIER`
// avoids threading mobile config through 22+ SessionRunner construction
// sites. Default `(threshold = DISABLED_SENTINEL, window = 0)` ⇒
// `current_outbound_batch_window` returns `None` and the runner's
// drain path stays identical to pre-slice baseline.

/// Sentinel for "battery awareness disabled" — mirrors
/// `veil_proto::ipc::MOBILE_LOW_BATTERY_THRESHOLD_DISABLED`.
pub const MOBILE_LOW_BATTERY_THRESHOLD_DISABLED: u8 = 255;

static MOBILE_LOW_BATTERY_THRESHOLD_PCT: AtomicU8 =
    AtomicU8::new(MOBILE_LOW_BATTERY_THRESHOLD_DISABLED);
static MOBILE_OUTBOUND_BATCH_WINDOW_MS: AtomicU32 = AtomicU32::new(0);

/// Mirror of `MobileConfig::MAX_OUTBOUND_BATCH_WINDOW_MS` — defended
/// at the global-signal layer so even a runtime call bypassing config
/// validation cannot stretch coalescing past 1 s (which would risk
/// stalling 1-second-cadence ROUTE_PROBE liveness).
pub const MAX_MOBILE_OUTBOUND_BATCH_WINDOW_MS: u32 = 1000;

/// Set the low-battery threshold. `None` disables every
/// battery-aware feature (route-probe throttle, maintenance throttle
/// outbound batching). Called from runtime startup + reload sites
/// alongside the existing `set_mobile_background_keepalive_multiplier`.
pub fn set_mobile_low_battery_threshold_pct(threshold: Option<u8>) {
    let v = threshold.unwrap_or(MOBILE_LOW_BATTERY_THRESHOLD_DISABLED);
    MOBILE_LOW_BATTERY_THRESHOLD_PCT.store(v, Ordering::Relaxed);
}

/// Set the outbound-batch window in milliseconds.
/// `0` disables coalescing. Clamped to `MAX_MOBILE_OUTBOUND_BATCH_WINDOW_MS`.
pub fn set_mobile_outbound_batch_window_ms(ms: u32) {
    let clamped = ms.min(MAX_MOBILE_OUTBOUND_BATCH_WINDOW_MS);
    MOBILE_OUTBOUND_BATCH_WINDOW_MS.store(clamped, Ordering::Relaxed);
}

/// Resolved coalescing window for the given battery reading. Returns
/// `Some(duration)` only when ALL of:
/// * outbound batch window is configured (`!= 0`)
/// * battery threshold is configured (`!= DISABLED`)
/// * battery is non-zero AND at-or-below the threshold (matches
///   `MobileConfig::battery_multiplier` semantics — `0` = AC sentinel
///   never throttle).
///
/// Otherwise `None` (coalescing off → fast path in session runner).
pub fn current_outbound_batch_window(battery_pct: u8) -> Option<std::time::Duration> {
    let ms = MOBILE_OUTBOUND_BATCH_WINDOW_MS.load(Ordering::Relaxed);
    if ms == 0 {
        return None;
    }
    let threshold = MOBILE_LOW_BATTERY_THRESHOLD_PCT.load(Ordering::Relaxed);
    if threshold == MOBILE_LOW_BATTERY_THRESHOLD_DISABLED {
        return None;
    }
    if battery_pct == 0 || battery_pct > threshold {
        return None;
    }
    Some(std::time::Duration::from_millis(ms as u64))
}

/// set the session-rotation **point** interval (seconds). `0`
/// disables rotation. Values 1..60 are clamped UP to
/// `MIN_SESSION_MAX_AGE_SECS` (the validation rule mirror — defends
/// against bypass). Called from runtime startup + reload with
/// the value from `cfg.session.max_age_secs`.
///
/// **Range-aware variant:** [`set_session_rotation_range`] — pass a
/// `(min, max)` pair (sampled uniformly per session).  This single-
/// value form is preserved for back-compat with the deprecated
/// `cfg.session.max_age_secs`; internally it sets `min = 0` so the
/// rotation-deadline computer falls to its legacy `±10 %` jitter path.
pub fn set_session_max_age_secs(secs: u64) {
    let stored = if secs == 0 {
        0
    } else {
        secs.max(MIN_SESSION_MAX_AGE_SECS)
    };
    SESSION_MAX_AGE_SECS.store(stored, Ordering::Relaxed);
    // Single-value mode: clear the min so SessionRotationDeadline
    // takes the legacy ±10 % jitter codepath.  Callers using the
    // range form must call `set_session_rotation_range` (which
    // overrides both atomics atomically-enough — we accept a brief
    // observable transient since this is a config-reload-time call).
    SESSION_MIN_AGE_SECS.store(0, Ordering::Relaxed);
}

/// Set the session-rotation **range** (seconds).  Each new session
/// draws a deadline uniformly from `[min, max]`.  Passing `(0, 0)`
/// disables rotation entirely.  Both values are clamped UP to
/// `MIN_SESSION_MAX_AGE_SECS` if non-zero (mirrors the validation
/// floor — defends against bypassed config push).  If `min > max`
/// after clamping, `min` is clamped down to `max`.
///
/// Called from runtime startup + reload with the resolved range from
/// `cfg.transport.rotation.{min,max}_lifetime_secs` (see
/// [`veil_cfg::TransportRotationConfig::resolved_range`]).
pub fn set_session_rotation_range(min_secs: u64, max_secs: u64) {
    let max_stored = if max_secs == 0 {
        0
    } else {
        max_secs.max(MIN_SESSION_MAX_AGE_SECS)
    };
    let min_stored = if min_secs == 0 {
        0
    } else {
        min_secs
            .max(MIN_SESSION_MAX_AGE_SECS)
            .min(max_stored.max(1))
    };
    // Order matters: store max first so a concurrent reader of
    // `current_session_rotation_range` never observes min > max
    // (it'd then clamp min to max and behave correctly).
    SESSION_MAX_AGE_SECS.store(max_stored, Ordering::Relaxed);
    SESSION_MIN_AGE_SECS.store(min_stored, Ordering::Relaxed);
}

/// Resolved session-rotation maximum interval right now. `0` =
/// rotation disabled.  Most callers want
/// [`current_session_rotation_range`] which returns both bounds.
pub fn current_session_max_age_secs() -> u64 {
    SESSION_MAX_AGE_SECS.load(Ordering::Relaxed)
}

/// **Test-only escape hatch** — set the rotation range without the
/// production-side floor clamp at [`MIN_SESSION_MAX_AGE_SECS`].
/// Integration tests need to exercise the deadline-fires-runner-closes
/// path in seconds, not minutes, but the production setter rightly
/// pushes sub-60 s values UP to defend against misconfig.  This bypass
/// preserves the production setter's invariants (production code does
/// NOT call this), but lets the test suite stage a 1-2 s rotation
/// window and verify the timer actually wakes the runner.
///
/// `#[doc(hidden)]` signals "internal API; not use in production code"
/// without needing the integration-test crate to live alongside `#[cfg(test)]`
/// (integration tests are external crates and can't see cfg-test items).
#[doc(hidden)]
pub fn set_session_rotation_range_unchecked_for_tests(min_secs: u64, max_secs: u64) {
    SESSION_MAX_AGE_SECS.store(max_secs, Ordering::Relaxed);
    SESSION_MIN_AGE_SECS.store(min_secs, Ordering::Relaxed);
}

/// Resolved `(min, max)` rotation range, or `(0, 0)` if disabled.
/// When `min == 0 && max > 0`, callers should treat this as legacy
/// single-value mode (point with ±10 % jitter); when both > 0,
/// callers sample uniformly from the closed interval.
pub fn current_session_rotation_range() -> (u64, u64) {
    let max = SESSION_MAX_AGE_SECS.load(Ordering::Relaxed);
    let min = SESSION_MIN_AGE_SECS.load(Ordering::Relaxed);
    // Defensive: if a concurrent setter writes out-of-order and we
    // see min > max, clamp.  Same reasoning as in `set_…_range`.
    if min > max && max > 0 {
        (max, max)
    } else {
        (min, max)
    }
}

/// randomise the keepalive interval by ±30% so that on-path DPI
/// cannot lock onto a periodic timing pattern. Each period draws a fresh
/// multiplier in `[0.7, 1.3]` uniformly, so the long-run mean equals the
/// configured base interval. A base of zero (keepalive disabled) returns
/// zero unchanged.
pub fn jitter_keepalive_interval(base: std::time::Duration) -> std::time::Duration {
    use rand_core::{OsRng, RngCore};
    if base.is_zero() {
        return base;
    }
    // Draw a u32 for uniform entropy, then map into [0.7, 1.3].
    let r = OsRng.next_u32() as f64 / u32::MAX as f64; // [0.0, 1.0]
    let scale = 0.7 + 0.6 * r; // [0.7, 1.3]
    let ms = (base.as_millis() as f64 * scale).round() as u64;
    std::time::Duration::from_millis(ms.max(1))
}

/// Returns the encrypted wire as a `PooledShared` — backing buffer
/// comes from the global pool and returns there on Drop after the wire
/// writer flushes to the socket. This closes the loop for the largest
/// outbound allocator (chat_node-style 60 KB frames): same buffer
/// recycles across hundreds of frames without touching the system
/// allocator. Callers send the `PooledShared` through `wire_tx`
///
pub fn apply_tx_cipher(
    frame: &[u8],
    cipher: &mut SessionCipher,
) -> Option<veil_bufpool::PooledShared> {
    use veil_crypto::session_cipher::CipherError;
    use veil_proto::header::HEADER_SIZE;
    if frame.len() < HEADER_SIZE {
        // Malformed sub-header frame (cannot decode a header to derive AAD).
        // Unreachable in practice — every frame carries a full header — but
        // guard the slice below. Wrap verbatim through a pool copy.
        return Some(veil_bufpool::pooled_shared_from_vec(frame.to_vec()));
    }
    // cycle-7 M1: a header-only frame (body_len == 0) is STILL sealed when a
    // cipher is present — the empty plaintext is AEAD'd to a 16-byte detached
    // tag (body_len becomes AEAD_OVERHEAD). Previously such frames
    // (Keepalive / KeepaliveAck / Backpressure / RekeyKeptInit / MlKemRekeyAck)
    // went out unauthenticated, so on a plaintext-TCP link an on-path attacker
    // could forge them to manipulate the rekey FSM / mask a dying transport.
    // The seal path below handles a zero-length plaintext slice correctly.
    //
    // WIRE COMPAT (flag-day): empty control frames grow by 16 bytes and a
    // pre-M1 peer's receiver rejects them (it expects no body). Roll out to all
    // nodes together — see `decrypt_frame_body_in_place`.
    let plaintext_body = &frame[HEADER_SIZE..];
    let h = decode_header(frame).ok()?;
    let aad = frame_aad(h.family, h.msg_type);
    // i: encrypt directly into the pool buffer instead of
    // allocating a fresh `Vec<u8>` via `cipher.seal(...)`. At 15 k frames/sec
    // on a bootstrap that path produced ~900 MiB/sec of small-arena churn —
    // bypassing the bufpool entirely and pinning dirty pages in jemalloc faster
    // than `dirty_decay_ms=1000` could release them. The pool buffer holds
    // `[header | plaintext | tag]`; we encrypt the plaintext slice in-place
    // append the 16-byte detached tag, and patch the header's body_len.
    let plaintext_len = plaintext_body.len();
    let ct_total = plaintext_len + veil_crypto::session_cipher::AEAD_OVERHEAD;
    let mut out_hdr = h;
    out_hdr.body_len = ct_total as u32;
    let mut out_pooled = veil_bufpool::global().acquire(HEADER_SIZE + ct_total);
    out_pooled
        .as_vec_mut()
        .extend_from_slice(&encode_header(&out_hdr));
    out_pooled.as_vec_mut().extend_from_slice(plaintext_body);
    // Encrypt the plaintext region of the pool buffer in place; on success
    // obtain the 16-byte tag to append. Bounds: we just wrote exactly
    // `plaintext_len` bytes after the header, so the slice is well-defined.
    let pt_start = HEADER_SIZE;
    let pt_end = HEADER_SIZE + plaintext_len;
    let tag =
        match cipher.seal_in_place_detached(&mut out_pooled.as_vec_mut()[pt_start..pt_end], &aad) {
            Ok(t) => t,
            Err(CipherError::NonceOverflow) => {
                log::error!("session.nonce_overflow: tx nonce counter exhausted — closing session");
                return None;
            }
            Err(_) => return None,
        };
    out_pooled.as_vec_mut().extend_from_slice(&tag);
    Some(out_pooled.into_shared())
}

/// Exact wire length after [`apply_tx_cipher`] seals one plaintext OVL1 frame.
fn encrypted_wire_len(frame_len: usize) -> Option<usize> {
    frame_len.checked_add(veil_crypto::session_cipher::AEAD_OVERHEAD)
}

// ── TLS record size padding ──────────────────────────────────────

/// Target wire sizes for coalesced (real + padding) writes. Chosen to match
/// the common HTTPS bucket sizes seen on the modern web: a single MSS
/// (≈1300 B), a small HTTP/2 page fragment (4 KB), and a TLS max record
/// (16 KB). A TLS 1.3 record of these lengths looks indistinguishable from
/// ordinary browser traffic to on-path DPI.
pub const TLS_BUCKET_SIZES: &[usize] = &[1300, 4096, 16384];

/// Minimum size of a padding frame: header + 1 body byte.
pub fn padding_frame_min_bytes() -> usize {
    veil_proto::header::HEADER_SIZE + 1
}

/// Cover-traffic emission interval (anti-DPI).
///
/// When a session has been silent for this long (no real frames pushed
/// to the priority queue), the runner emits a `SessionMsg::Padding`
/// frame — encrypted, dropped on the receiving side, but visible on the
/// wire as a TLS record of one of the bucket sizes. This breaks
/// "traffic-silence" fingerprinting by an on-path censor that uses
/// quiet periods to detect off-line peers, and stops a censor from
/// learning the user's activity pattern (which DPI can correlate with
/// other side-channels). Random ±25 % jitter on top so the cover-frame
/// cadence isn't itself a fingerprint.
///
/// Picked at 30 s — far below `idle_timeout` (90 s default) so cover
/// frames can't satisfy idle-keepalive accounting and trigger
/// false-positive "session healthy" signals; far above keepalive
/// jitter (~30 s) so cover frames don't compound with keepalive
/// bursts. Tuned for budget Android: 32 B padding × 1 frame / 30 s ×
/// (TLS bucket overhead = 1300 B) ≈ 43 B/s of background traffic per
/// peer, ≈ 300 B/s for a 7-peer mesh — negligible cost on cellular.
pub const COVER_TRAFFIC_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// Apply ±25 % uniform jitter to the cover-traffic interval so the
/// emission cadence isn't itself a tracer. Returns `Duration::ZERO`
/// when the base is zero (cover disabled).
pub fn jitter_cover_interval(base: std::time::Duration) -> std::time::Duration {
    if base.is_zero() {
        return std::time::Duration::ZERO;
    }
    use rand_core::{OsRng, RngCore};
    // Map the upper 24 bits of a u32 into [-0.25, +0.25] so jitter is
    // uniform. ((raw >> 8) - 2^23) / 2^25 = signed [-0.25, +0.25-ε].
    let raw = OsRng.next_u32();
    let signed = ((raw >> 8) as i64) - (1i64 << 23);
    let frac = signed as f64 / (1u64 << 25) as f64; // [-0.25, +0.25)
    let scaled = (base.as_secs_f64() * (1.0 + frac)).max(0.001);
    std::time::Duration::from_secs_f64(scaled)
}

/// Build an encrypted `SessionMsg::Padding` frame whose total wire length
/// (header + encrypted body + AEAD overhead) equals exactly `target` bytes.
/// Returns `None` when the target is too small to fit a valid padding frame
/// or when encryption fails.
pub fn build_padding_wire(
    target: usize,
    cipher: &mut SessionCipher,
) -> Option<veil_bufpool::PooledShared> {
    use veil_crypto::session_cipher::AEAD_OVERHEAD;
    use veil_proto::header::HEADER_SIZE;
    // Wire layout: HEADER_SIZE plaintext header || ciphertext (= body_len - AEAD_OVERHEAD plaintext + AEAD tag)
    // So plaintext body length = target - HEADER_SIZE - AEAD_OVERHEAD.
    let plaintext_body_len = target
        .checked_sub(HEADER_SIZE)?
        .checked_sub(AEAD_OVERHEAD)?;
    if plaintext_body_len == 0 || plaintext_body_len > u32::MAX as usize {
        return None;
    }
    let mut body = vec![0u8; plaintext_body_len];
    {
        use rand_core::{OsRng, RngCore};
        OsRng.fill_bytes(&mut body);
    }
    let mut hdr = FrameHeader::new(FrameFamily::Session as u8, SessionMsg::Padding as u16);
    hdr.body_len = plaintext_body_len as u32;
    let mut frame = Vec::with_capacity(HEADER_SIZE + plaintext_body_len);
    frame.extend_from_slice(&encode_header(&hdr));
    frame.extend_from_slice(&body);
    apply_tx_cipher(&frame, cipher)
}

/// Pick the smallest bucket size that fits `wire_len` with enough slack for a
/// minimum-size padding frame. Returns `None` when the wire already exceeds
/// the largest bucket (no padding added — send as-is).
pub fn pick_tls_bucket(wire_len: usize) -> Option<usize> {
    let min_pad = padding_frame_min_bytes() + veil_crypto::session_cipher::AEAD_OVERHEAD;
    for &bucket in TLS_BUCKET_SIZES {
        // Either exactly fits (no padding needed) or has room for minimum padding.
        if wire_len == bucket {
            return Some(bucket);
        }
        if wire_len + min_pad <= bucket {
            return Some(bucket);
        }
    }
    None
}

/// Wire length after optional TLS-bucket padding, without advancing the cipher.
fn padded_wire_len(real_wire_len: usize) -> usize {
    if !padding_enabled() {
        return real_wire_len;
    }
    pick_tls_bucket(real_wire_len).unwrap_or(real_wire_len)
}

/// Coalesce a real encrypted wire with a padding frame sized so the combined
/// output equals the next TLS bucket. When `tx_cipher` is absent (pre-session
/// handshake), padding is globally disabled via [`set_padding_enabled`], or no
/// bucket fits, the wire is returned unchanged.
pub fn coalesce_with_padding(real_wire: &[u8], tx_cipher: Option<&mut SessionCipher>) -> Vec<u8> {
    if !padding_enabled() {
        return real_wire.to_vec();
    }
    let Some(cipher) = tx_cipher else {
        return real_wire.to_vec();
    };
    let Some(bucket) = pick_tls_bucket(real_wire.len()) else {
        return real_wire.to_vec();
    };
    if real_wire.len() == bucket {
        return real_wire.to_vec();
    }
    let pad_target = bucket - real_wire.len();
    let Some(pad_wire) = build_padding_wire(pad_target, cipher) else {
        return real_wire.to_vec();
    };
    debug_assert_eq!(
        real_wire.len() + pad_wire.len(),
        bucket,
        "padding size calculation mismatch: real={}, pad={}, bucket={}",
        real_wire.len(),
        pad_wire.len(),
        bucket,
    );
    let mut combined = Vec::with_capacity(bucket);
    combined.extend_from_slice(real_wire);
    combined.extend_from_slice(&pad_wire);
    combined
}

impl SessionRunner {
    /// Read OVL1 frames from the stream, dispatch each one, and write
    /// responses back. Also drains the `outbox` — frames queued by the
    /// runtime (e.g. periodic ROUTE_PROBEs) are written directly to the peer.
    /// Returns when the stream is closed or an I/O error occurs.
    pub async fn run(&mut self) {
        let mut hdr_buf = [0u8; veil_proto::header::HEADER_SIZE];
        // WRR priority queue for outgoing frames from the runtime outbox.
        // Weights are configurable via SessionConfig.qos_weights.
        let mut pq = if let Some(m) = &self.metrics {
            PriorityQueue::with_capacity_and_drop_counter(
                self.qos_weights,
                crate::priority_queue::DEFAULT_MAX_DEPTH,
                m.priority_queue_drops_counter(),
            )
        } else {
            PriorityQueue::new(self.qos_weights)
        };
        // Pending RPC responses: request_id → oneshot sender.
        // Bounded to max_pending_responses; entries older than
        // pending_response_ttl are evicted to prevent DoS via fake
        // request_ids.  See `pending_response_table.rs` for the
        // asymmetry between try_recv-drain and select-arm insert paths.
        let mut pending_responses = crate::pending_response_table::PendingResponseTable::new(
            self.max_pending_responses,
            self.pending_response_ttl,
        );

        // Take the outbox channels out of self so they are dropped when run exits
        // (any code path, including early returns). This closes the mpsc receiver
        // immediately after the session loop ends, so SessionTxRegistry::send_to
        // will see TrySendError::Closed instead of silently queuing frames into a
        // dead channel that nobody reads (ghost-session window).
        let mut outbox = self.outbox.take();
        let mut rpc_outbox = self.rpc_outbox.take();
        // hot-standby swap inbox, taken out for the same reason.
        let mut swap_rx = self.hot_standby.swap_rx.take();

        // ── b: reader/writer split ─────────────────────────────────
        // Architectural fix for the symmetric `write_all` deadlock (testnet
        // Instead of one task that interleaves reads and
        // writes on `self.stream` (which can park in `write_all` while
        // peer's recv buffer is full → kernel buffers fill on both sides
        // → cross-host deadlock), we split the stream and run the WRITE
        // half in a dedicated task fed by a bounded channel. The main
        // loop owns only the READ half and the channel sender — it
        // CANNOT block on a slow writer because `try_send` is sync.
        //
        // On hot-standby swap (`NextInput::SwapStream`) we drop the
        // current `wire_tx` (writer task exits when channel closes)
        // await the JoinHandle, then split + spawn anew with the
        // replacement transport.
        let stream = std::mem::replace(&mut self.stream, broken_stream_sentinel());
        let (mut read_half, write_half) = tokio::io::split(stream);
        let (mut wire_tx, wire_rx) =
            mpsc::channel::<veil_bufpool::PooledShared>(WIRE_CHANNEL_CAPACITY);
        let mut writer_handle = spawn_writer_task(
            write_half,
            wire_rx,
            self.metrics.clone(),
            Arc::clone(&self.logger),
            hex_short(&self.peer_id),
        );
        // stage (c): consecutive-error counter for
        // on_primary_write_error. Not reset on successful write — a
        // half-dead primary may flap between OK and err, and we want the
        // trigger to fire on cumulative failure within the session's life.
        // Slice 29: counter + threshold compare encapsulated in
        // `WriteErrorTracker`.  Threshold pulled from hot-standby config
        // — zero disables auto-trigger (default for sessions without a
        // hot-standby setup).
        let mut write_error_count = crate::write_error_tracker::WriteErrorTracker::new(
            self.hot_standby.auto_trigger_after_write_errors,
        );
        // OnceTrigger fires once per stall event — caller resets it
        // on any incoming frame so a subsequent stall can re-fire.
        let mut stall_trigger = crate::once_trigger::OnceTrigger::new();
        // Ledger of the OLDEST unacked outgoing Keepalive timestamp.
        // Armed when we send a Keepalive and no prior probe is pending;
        // cleared on incoming KeepaliveAck.  If
        // `now - oldest >= keepalive_probe_timeout` AND no ack has
        // arrived, the TX leg of the primary is considered broken and
        // we fire the hot-standby trigger.  Distinct from rx_stall:
        // rx_stall is masked by the peer's own keepalives flowing IN
        // while our keepalives fail to go OUT (Windows Firewall
        // half-block scenario).  `try_arm` preserves the oldest-armed
        // invariant — a keepalive sent while a probe is already in
        // flight does NOT advance the timestamp.
        let mut pending_keepalive_probe = crate::keepalive_emit::PendingKeepaliveProbe::new();
        let mut keepalive_probe_trigger = crate::once_trigger::OnceTrigger::new();
        // Per-episode warm-probe swap-attempt counter (M5 re-eval). Counts
        // warm-probe spawns since the FIRST keepalive-probe-timeout fire of the
        // current zombie episode. Reset to 0 on inbound KeepaliveAck (TX
        // confirmed) and on a completed SwapStream (TX re-established).
        let mut keepalive_swap_attempts: u32 = 0u32;
        // Timeout = 1 × keepalive_interval. A healthy peer acks within
        // < 1 s on a LAN, so waiting one full interval for the ack is
        // already generous. Initial c.2.2 shipped with 2 ×
        // interval, but two-host Windows validation on a LAN showed
        // station's TCP giving up the RST at ~25-30s after the firewall
        // block, which beat the 2 × 10s = 20s probe by a few seconds
        // — we want the probe to fire EARLIER than the OS's TCP close
        // so HandoffInit can still travel on the live primary.
        let keepalive_probe_timeout = self.keepalive_interval;

        // ── Backpressure state ────────────────────────────────────
        // When the peer exceeds its rate limit, we send a Backpressure
        // control frame so the peer marks us as congested and
        // redistributes traffic.  Rate-limit drops NEVER escalate to
        // violations — a relay peer can't reduce forwarded traffic, so
        // banning it would worsen the situation.
        const BP_SIGNAL_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(1);
        let mut bp_signal = crate::backpressure_signal::BackpressureSignal::new(BP_SIGNAL_COOLDOWN);

        // ── session alias registration ────────────────────────────
        // AliasGuard unregisters both aliases when run exits via any
        // path (early return, panic, normal exit).
        let _alias_guard = self.register_session_aliases_with_drop_guard();

        // ── send SESSION_TICKET immediately after session attaches ─────
        if self
            .send_pending_session_ticket(&wire_tx, &mut write_error_count)
            .is_err()
        {
            return;
        }

        // ── Rekey state ───────────────────────────────────────────────────────
        let mut rekey = crate::rekey_context::RekeyContext::new(
            self.rekey.bytes_threshold,
            self.rekey.time_threshold_secs,
        );
        // hardening: after responder switches to NEW
        // rx_cipher on rekey, the OLD cipher must be retained briefly
        // so in-flight initiator frames sent BEFORE the initiator
        // received the RekeyAck (and thus still encrypted with OLD tx)
        // can be decrypted via fallback. Without this, the cluster
        // experiences a transient AEAD-failure storm at every rekey
        // (~21 rekeys per session at 18 MiB/s sustained traffic).
        // See TASKS.md incident note.
        //
        // (fix): grace is **time-based** rather
        // than frame-count-based. Frame-count grace exhausted faster
        // than RTT covers RekeyAck arrival under chat-node load —
        // 256 frames @ ~80-100 fps = ~3 s of cover, but cross-country
        // VPS RTT can spike past that during busy hours, leading to
        // sporadic decrypt-failure session teardowns (incident note
        // 30 s window adapts naturally to traffic rate
        // (high or idle) and comfortably covers any realistic
        // RekeyInit→RekeyAck round-trip. Memory cost: one extra
        // SessionCipher per session for ≤ 30 s — negligible.
        // keep a small ring of previous rx
        // ciphers so back-to-back rekeys (gen-N-1 already in grace
        // when gen-N rekey starts) do not orphan in-flight frames
        // encrypted with gen-N-2 and trigger a session-teardown
        // decrypt-failure storm.  `RekeyRxGraceBuffer` is a FIFO ring
        // with TTL prune + cap-evict + newest-first try-open.
        const REKEY_RX_PREV_CAP: usize = 16;
        const REKEY_RX_GRACE_DURATION: std::time::Duration = std::time::Duration::from_secs(30);
        let mut rx_cipher_prev = crate::rekey_rx_grace_buffer::RekeyRxGraceBuffer::new(
            REKEY_RX_PREV_CAP,
            REKEY_RX_GRACE_DURATION,
        );

        // ── ML-KEM rekey state ─────────────────────────────────────
        let mut mlkem_rekey = crate::mlkem_rekey_context::MlKemRekeyContext::new(
            MLKEM_REKEY_BYTES_THRESHOLD,
            MLKEM_REKEY_TIME_THRESHOLD_SECS,
        );

        // ── keepalive / idle-timeout state ───────────────────────────
        let keepalive_interval = self.keepalive_interval;
        let idle_timeout = self.idle_timeout;
        let keepalive_enabled = !keepalive_interval.is_zero();
        let idle_enabled = idle_timeout > std::time::Duration::ZERO;
        // rotation deadline is checked in the Timer arm
        // so timer must fire even when keepalive + idle_timeout are
        // both disabled (rare but happens in test fixtures + relay-
        // only configs). Without this, a keepalive-disabled session
        // with rotation configured would never rotate.
        // Note: session_rotation is computed below; we don't have it yet here
        // so re-read the global directly for the timer-enabled flag.
        let rotation_enabled = current_session_max_age_secs() > 0;
        // Cover-traffic only kicks in when keepalive is also enabled — a
        // keepalive-disabled session is short-lived and doesn't need
        // anti-DPI cover. Tied to `tx_cipher.is_some`: the padding
        // frame must be encrypted, so we cannot emit cover
        // before the handshake completes.
        let cover_enabled = keepalive_enabled;
        let timer_enabled = keepalive_enabled || idle_enabled || rotation_enabled || cover_enabled;
        // SessionTimers' read-only `last_rx` accessor enforces the
        // gate-Test-5 invariant: only `note_frame_received` /
        // `note_swap` can advance the ticker. See `timers.rs` doc.
        let mut timers = crate::timers::SessionTimers::new(keepalive_interval, idle_timeout);

        // ── + 483.1: battery + background-factor adjusted keepalive ──
        const BATTERY_CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);
        let mut battery_keepalive =
            crate::battery_adjusted_keepalive::BatteryAdjustedKeepalive::new(
                self.mobile.base_keepalive_interval,
                self.mobile.battery_keepalive_scale_low as f64,
                self.mobile.battery_keepalive_scale_medium as f64,
                self.mobile.battery_threshold_low,
                self.mobile.battery_threshold_medium,
                BATTERY_CHECK_INTERVAL,
            );

        // deferred : outbound-batch coalescer holds the timestamp of
        // the last priority-queue drain pass + provides the "should
        // this drain be deferred?" check.  Slice 30 (architecture
        // backlog): logic encapsulated in
        // `crate::outbound_batch_coalescer::OutboundBatchCoalescer`.
        let mut outbound_coalescer = crate::outbound_batch_coalescer::OutboundBatchCoalescer::new(
            tokio::time::Instant::now(),
        );

        // connection-rotation deadline. Computed once
        // at session start from the global SESSION_MAX_AGE_SECS
        // (set from config); when reached, session closes
        // gracefully and the outbound connector reconnects (fresh
        // TCP+TLS handshake with the same Chrome ClientHello
        // fingerprint). Defeats the long-lived-connection DPI
        // signature that distinguishes veil-style sessions
        // from normal HTTPS browsing patterns.
        //
        // Per-session jitter (±10%) so a fleet of nodes doesn't
        // all rotate at the same wall-clock instant — would
        // produce a synchronized spike that's itself a
        // fingerprint. Jitter is computed once per session
        // (not per timer tick) so rotation cadence stays
        // predictable for a single session, just unpredictable
        // across the fleet.
        let mut session_rotation =
            crate::rotation_deadline::SessionRotationDeadline::compute(tokio::time::Instant::now());

        loop {
            // ── Outbox drain + header read (concurrent) ───────────────────────
            //
            // We select between:
            // (a) reading a header byte from the peer stream, and
            // (b) receiving a priority-tagged frame from the outbox.
            //
            // Because read_exact is not cancel-safe we use a two-phase approach:
            // peek the first byte (cancel-safe), then read the rest after the
            // select resolves.
            let first_byte: u8;
            loop {
                // Outbox drain returns `ControlFlow::Break` if the Sender
                // was dropped — that means run must exit.
                if let Some(ref mut outbox) = outbox
                    && let std::ops::ControlFlow::Break(()) =
                        self.drain_outbox_into_pq(outbox, &mut pq)
                {
                    return;
                }
                if let Some(ref mut rpc_outbox) = rpc_outbox {
                    self.drain_rpc_outbox_into_pq(rpc_outbox, &mut pq, &mut pending_responses);
                }
                // ── keepalive / idle timeout checks ──────────────────
                if timer_enabled {
                    let now = tokio::time::Instant::now();
                    // Check idle timeout (when enabled).
                    if timers.idle_timeout_elapsed(now) {
                        self.logger.warn(
                            "session.idle_timeout",
                            format!("peer_id={}", hex_short(&self.peer_id)),
                        );
                        return;
                    }
                    // Hard liveness-ceiling backstop (M5 zombie reaper). When a
                    // keepalive-probe timeout fires the hot-standby trigger but the
                    // warm probe can't recover a vanished NAT'd peer, the probe's
                    // `note_swap` keeps refreshing `last_rx` so `idle_timeout` above
                    // never fires; the outbox rx stays alive
                    // (`SessionTxRegistry::has_session` ⇒ true) and EVERY reconnect
                    // from that peer is deduped (the observed 3000+/peer storm).
                    // `liveness_ceiling_elapsed` ignores swaps — it tracks only
                    // genuine peer frames — so a peer that has sent nothing real for
                    // 3×idle_timeout is torn down unconditionally, releasing the tx
                    // so the next reconnect succeeds. Mesh-safe by construction: a
                    // live mesh session receives genuine keepalive frames every
                    // `keepalive_interval` (≤ idle_timeout), so its genuine-RX ticker
                    // never ages into the ceiling.
                    if timers.liveness_ceiling_elapsed(now) {
                        self.logger.warn(
                            "session.liveness_ceiling",
                            format!(
                                "peer_id={} — no genuine frame past the liveness ceiling; \
                                 reaping zombie session to release its tx",
                                hex_short(&self.peer_id),
                            ),
                        );
                        return;
                    }
                    // stage (c.2): proactive rx-stall trigger.
                    // Fire when rx has been silent for 2/3 of idle_timeout —
                    // the configured idle window gives us the deadline
                    // budget; at 2/3 of it we still have 1/3 · idle_timeout
                    // left for the warm probe to complete its handshake
                    // before legacy close kicks in.
                    //
                    // Gated on `idle_enabled` alone — if the operator
                    // configured an idle timeout, they've agreed that
                    // silence past that point is degradation.
                    if timers.rx_stall_elapsed(now) && stall_trigger.try_fire() {
                        self.on_primary_rx_stall();
                    }
                    // Opportunistic grace-ring prune (audit batch 2026-05-21
                    // Phase E17): RekeyRxGraceBuffer::prune_expired runs
                    // only on decrypt attempts.  On a stuck rekey + silent
                    // peer (no inbound frames), old rx ciphers sit in the
                    // buffer for the full 30 s grace window unused.
                    // Cover-due tick fires every cover-interval (~30 s), so
                    // this is essentially "prune once per cover cycle" —
                    // zero hot-path cost, bounds worst-case retention.
                    rx_cipher_prev.prune_expired(now);

                    // Cover-traffic emission (anti-DPI): SessionMsg::Padding
                    // frame when the line has been silent for cover-interval.
                    if self.crypto.tx_cipher.is_some() && timers.cover_due_and_reschedule(now) {
                        pq.push(
                            veil_proto::priority::BACKGROUND,
                            crate::cover_traffic::build_cover_frame(),
                        );
                    }
                    // Enqueue a keepalive if the interval has elapsed.
                    // `PendingKeepaliveProbe::try_arm` preserves the
                    // oldest-armed timestamp on subsequent calls.
                    if timers.keepalive_due_and_reschedule(now) {
                        pq.push(
                            veil_proto::priority::INTERACTIVE,
                            veil_bufpool::pooled_shared_from_vec(
                                crate::keepalive_emit::build_keepalive_frame(),
                            ),
                        );
                        let was_pending_set = pending_keepalive_probe.try_arm(now);
                        // Debug-level so production logs aren't spammed
                        // with a pair of lines per keepalive cycle. The
                        // user-visible signal is `trigger_raised
                        // reason=keepalive_probe_timeout` which fires
                        // only when something is actually wrong.
                        self.logger.debug(
                            "session.keepalive.sent",
                            format!(
                                "peer_id={} pending_was_set={}",
                                hex_short(&self.peer_id),
                                was_pending_set
                            ),
                        );
                    }
                    // stage (c.2.2): keepalive-probe timeout
                    // fires the hot-standby trigger when our keepalives
                    // have been going unacked for long enough to
                    // conclude the TX leg is broken.
                    //
                    // Audit batch 2026-05-24 (M5): when no warm-probe
                    // can be spawned (no controller, no `alt_uri`,
                    // flap-damped, …) the session is zombie-alive — TCP
                    // read loop keeps parking on `read_u8` (no EOF
                    // until OS keepalive ~11 min default), `outbox` rx
                    // stays alive so `SessionTxRegistry::has_session`
                    // reports `true`, and `outbound_connector` skips
                    // reconnect.  Symmetric-direction dedup (Phase E20)
                    // means the peer can't recover us either: its
                    // outbound is policy-rejected.  Net: permanent split
                    // until daemon restart (testnet node3 was stuck like
                    // this for 4h56m; first M5 fix gated on `controller.
                    // is_none()` alone and regressed within 30 min because
                    // testnet hot-standby IS wired but without an `alt_uri`).
                    // Fix: tear down whenever the trigger fires and the
                    // controller couldn't spawn a warm probe — that's
                    // the signal that no failover is available, and
                    // letting the session zombie indefinitely is strictly
                    // worse than forcing a fresh reconnect.
                    // Stage A: FIRST probe-timeout fire of the episode — arm the
                    // trigger, attempt the first warm-probe spawn, count it. Do
                    // NOT return here (re-eval below decides reap).
                    if keepalive_enabled
                        && !keepalive_probe_trigger.has_fired()
                        && keepalive_probe_timeout > std::time::Duration::ZERO
                        && let Some(t) = pending_keepalive_probe.oldest()
                        && now.duration_since(t) >= keepalive_probe_timeout
                        && keepalive_probe_trigger.try_fire()
                    {
                        let spawned = self.fire_hot_standby_trigger("keepalive_probe_timeout");
                        keepalive_swap_attempts = keepalive_swap_attempts.saturating_add(1);
                        self.logger.info(
                            "session.keepalive.probe_fired",
                            format!(
                                "peer_id={} warm_probe_spawned={spawned} attempt={keepalive_swap_attempts}",
                                hex_short(&self.peer_id),
                            ),
                        );
                    }
                    // Stage B: RE-EVAL each keepalive tick while the trigger stays
                    // fired (no KeepaliveAck cleared the ledger). The dedicated
                    // probe wake is dropped after first fire
                    // (compute_sleep_deadline gates on !fired) so this arm is
                    // woken by next_keepalive every keepalive_interval; budget
                    // ~2×probe_timeout + 1×interval. Re-spawn (bump counter) each
                    // tick until an ack clears it or the helper says reap.
                    else if keepalive_enabled
                        && keepalive_probe_trigger.has_fired()
                        && keepalive_probe_timeout > std::time::Duration::ZERO
                        && let Some(t) = pending_keepalive_probe.oldest()
                    {
                        let probe_age = now.duration_since(t);
                        if probe_age >= keepalive_probe_timeout {
                            let spawned = self.fire_hot_standby_trigger("keepalive_probe_timeout");
                            keepalive_swap_attempts = keepalive_swap_attempts.saturating_add(1);
                            let genuine_age = timers.genuine_rx_age(now);
                            if should_reeval_teardown(
                                probe_age,
                                keepalive_probe_timeout,
                                keepalive_swap_attempts,
                                KEEPALIVE_SWAP_ATTEMPT_CEILING,
                                genuine_age,
                                spawned,
                            ) {
                                self.logger.info(
                                    "session.keepalive.timeout_close",
                                    format!(
                                        "peer_id={} — probe unacked {}ms, genuine_rx age {}ms, swap_attempts={} (ceiling {}); reaping zombie (tx-wedge if genuine fresh)",
                                        hex_short(&self.peer_id),
                                        probe_age.as_millis(),
                                        genuine_age.as_millis(),
                                        keepalive_swap_attempts,
                                        KEEPALIVE_SWAP_ATTEMPT_CEILING,
                                    ),
                                );
                                return;
                            }
                        }
                    }
                }
                // Rekey-threshold checks — both no-op unless a fresh
                // rekey is needed (X25519 cipher rotation +
                // nonce-watermark, PQ E2E key rotation respectively).
                self.maybe_initiate_x25519_rekey(&mut rekey, &mut pq);
                self.maybe_initiate_mlkem_rekey(&mut mlkem_rekey, &mut pq);
                // ── Step 2: flush priority queue to the wire ─────────────────
                // cap drained frames per pass so a deep pq doesn't
                // starve the read step (every iteration through this pass blocks
                // socket reads for the duration; if pq.len > 1000 that's
                // seconds of read-starvation under chat-node load, which is
                // exactly the window during which the deadlock above developed).
                //
                // deferred : when battery is below threshold
                // AND outbound-batch window is configured AND the queue head
                // priority is BULK or BACKGROUND (≥ 2), the runner defers
                // the drain pass until `last_drain_ts + window`. The drain
                // skip block is structured so that ALL existing logic stays
                // identical when the feature is disabled (default: window=0
                // ⇒ `current_outbound_batch_window` returns None ⇒
                // `coalesce_until` is None ⇒ `coalesce_active` is false ⇒
                // drain proceeds unconditionally as).
                let coalesce_window = current_outbound_batch_window(battery_keepalive.last_level());
                let now_for_drain = tokio::time::Instant::now();
                let coalesce_active = outbound_coalescer.is_coalescing(
                    now_for_drain,
                    coalesce_window,
                    pq.peek_priority(),
                );
                let coalesce_until =
                    outbound_coalescer.coalesce_deadline(coalesce_window, pq.peek_priority());
                let mut drained_this_pass = 0usize;
                // Encrypt several already-queued OVL1 frames back-to-back and
                // add ONE padding frame for the whole group. Small circuit-data
                // frames are ~420 B on this layer, so this packs 3 into the
                // 1300-B bucket (or a larger ready burst into 4096/16384) instead
                // of spending a separate 1300-B bucket on every 300-B payload.
                // There is no waiting window here: only frames already in `pq`
                // are grouped, so interactive latency does not increase.
                const ENCRYPTED_BATCH_FRAMES: usize = PQ_DRAIN_FRAMES_PER_PASS;
                let encrypted_pass = self.crypto.tx_cipher.is_some();
                let drain_cap = if encrypted_pass {
                    ENCRYPTED_BATCH_FRAMES
                } else {
                    PQ_DRAIN_FRAMES_PER_PASS
                };
                let mut encrypted_batch_frames = Vec::new();
                let mut encrypted_batch_wire_len = 0usize;
                while !coalesce_active
                    && drained_this_pass < drain_cap
                    // Do not pop a frame unless the dedicated writer can accept
                    // it. Previously a full (but healthy) channel was treated as
                    // a write failure below and tore down the whole obfs4/TCP
                    // session during a short bulk burst.
                    && wire_tx.capacity() > 0
                    && let Some(outgoing) = pq.pop()
                {
                    drained_this_pass += 1;
                    // Capture the plaintext frame before any encryption.
                    self.dispatcher.capture_outbound(self.peer_id, &outgoing);
                    if self.crypto.tx_cipher.is_some() {
                        let Some(next_len) = encrypted_wire_len(outgoing.len())
                            .and_then(|n| encrypted_batch_wire_len.checked_add(n))
                        else {
                            self.on_primary_write_error(&mut write_error_count);
                            return;
                        };
                        encrypted_batch_wire_len = next_len;
                        encrypted_batch_frames.push(outgoing.clone());
                    } else {
                        // No encryption: convert Arc-backed bytes to owned Vec
                        // for the wire channel. Padding is not applied
                        // pre-handshake because the padding frame itself
                        // is an encrypted session frame.
                        let tx_len = outgoing.len() as u64;
                        // outgoing is already a PooledShared — pass through.
                        match Self::push_wire(&wire_tx, outgoing.clone(), &self.metrics) {
                            Ok(()) => {}
                            Err(mpsc::error::TrySendError::Full(_)) => continue,
                            Err(mpsc::error::TrySendError::Closed(_)) => {
                                self.on_primary_write_error(&mut write_error_count);
                                return;
                            }
                        }
                        if let Some(m) = &self.metrics {
                            m.add_transport_bytes_tx(tx_len);
                        }
                        rekey.record_bytes(tx_len);
                        mlkem_rekey.record_bytes(tx_len);
                    }
                }
                if !encrypted_batch_frames.is_empty() {
                    // Check the operator bandwidth bucket BEFORE encrypting. A
                    // dropped encrypted frame burns the implicit AEAD nonce and
                    // permanently desynchronises the session.
                    let planned_wire_len = padded_wire_len(encrypted_batch_wire_len);
                    if !self.dispatcher.allow_outbound_bandwidth(planned_wire_len) {
                        continue;
                    }
                    let cipher = self
                        .crypto
                        .tx_cipher
                        .as_mut()
                        .expect("encrypted pass must retain its TX cipher");
                    let mut encrypted_batch = Vec::with_capacity(encrypted_batch_wire_len);
                    for frame in encrypted_batch_frames {
                        let enc = match apply_tx_cipher(&frame, cipher) {
                            Some(enc) => enc,
                            None => return, // cipher/header error — close session
                        };
                        encrypted_batch.extend_from_slice(&enc);
                    }
                    // One standard HTTPS-sized bucket for the concatenated real
                    // frames. The receiver already parses consecutive encrypted
                    // OVL1 frames, then silently consumes the final padding frame.
                    let wire = coalesce_with_padding(&encrypted_batch, Some(cipher));
                    let tx_len = wire.len() as u64;
                    let wire_pool = veil_bufpool::pooled_shared_from_vec(wire);
                    if Self::push_wire(&wire_tx, wire_pool, &self.metrics).is_err() {
                        // Capacity was checked before popping/encrypting. A
                        // failure now therefore means the writer closed (or
                        // an invariant broke); encrypted frames cannot be
                        // dropped without desynchronising the session cipher.
                        self.on_primary_write_error(&mut write_error_count);
                        return;
                    }
                    if let Some(m) = &self.metrics {
                        m.add_transport_bytes_tx(tx_len);
                    }
                    rekey.record_bytes(tx_len);
                    mlkem_rekey.record_bytes(tx_len);
                }
                // deferred : stamp the coalescer's last-drain time after a
                // successful drain pass (any frames emitted). Doing it
                // unconditionally would let the deadline creep forward
                // even on no-op iterations — caller would never get the
                // delay benefit because the deadline keeps getting pushed.
                if drained_this_pass > 0 {
                    outbound_coalescer.record_drain(tokio::time::Instant::now());
                }
                // `compute_sleep_deadline` folds up to 7 independent
                // timer sources (battery, idle, keepalive, cover, rx-
                // stall trigger, keepalive-probe timeout, coalesce
                // window).  See its docstring for the full matrix.
                let sleep_until = Self::compute_sleep_deadline(
                    &timers,
                    &battery_keepalive,
                    timer_enabled,
                    keepalive_enabled,
                    keepalive_probe_trigger.has_fired(),
                    keepalive_probe_timeout,
                    pending_keepalive_probe.oldest(),
                    stall_trigger.has_fired(),
                    coalesce_until,
                    session_rotation.deadline(),
                );
                match await_next_input(
                    &mut read_half,
                    outbox.as_mut(),
                    rpc_outbox.as_mut(),
                    swap_rx.as_mut(),
                    sleep_until,
                    &wire_tx,
                )
                .await
                {
                    NextInput::Byte(b) => {
                        first_byte = b;
                        break;
                    }
                    NextInput::OutboxFrame((prio, frame)) => {
                        pq.push(prio, frame);
                        continue;
                    }
                    NextInput::SwapStream(new_stream) => {
                        // Tear-down + re-spawn lifecycle is mechanical;
                        // rebind locals from the tuple result, reset
                        // timer + trigger, continue.
                        let (new_read, new_tx, new_handle) = self
                            .swap_transport_plumbing(new_stream, wire_tx, writer_handle)
                            .await;
                        read_half = new_read;
                        wire_tx = new_tx;
                        writer_handle = new_handle;
                        timers.note_swap(tokio::time::Instant::now());
                        // stage (c.2): the swap clears any prior
                        // rx-stall condition, so a subsequent stall can
                        // legitimately re-fire the trigger.
                        stall_trigger.clear();
                        // A make-before-break swap re-established TX on a fresh
                        // path, so the stale keepalive-probe ledger must reset —
                        // else should_reeval_teardown trips on the NEXT keepalive
                        // tick of the new transport (swap-reap race).
                        pending_keepalive_probe.clear();
                        keepalive_probe_trigger.clear();
                        keepalive_swap_attempts = 0;
                        continue;
                    }
                    NextInput::RpcRequest(req) => {
                        let now = tokio::time::Instant::now();
                        // Symmetric with the drain-loop path: TTL-evict AND
                        // capacity-evict before insert, so single-at-a-time
                        // arrivals via this select-arm can't transiently push
                        // the table past `capacity`.
                        pending_responses.evict_expired(now);
                        pending_responses.evict_oldest_if_at_capacity();
                        pending_responses.insert(req.request_id, req.response_tx, now);
                        pq.push(
                            veil_proto::priority::INTERACTIVE,
                            veil_bufpool::pooled_shared_from_vec(req.frame),
                        );
                        continue;
                    }
                    // Timer fires for keepalive/idle checks; also evict stale RPC
                    // response slots so they don't accumulate during quiet periods
                    // when no new RPC requests arrive.
                    NextInput::Timer => {
                        let now = tokio::time::Instant::now();
                        // ── connection-rotation deadline ──────────
                        // Defeats long-lived-connection DPI fingerprint by
                        // forcing fresh TCP+TLS handshake every N minutes.
                        //
                        // **Phase 2 (Q.7 audit batch)**: prefer a hot-
                        // standby make-before-break swap if an `alt_uri`
                        // is registered for the peer.  This gives true
                        // zero-gap rotation — the new transport completes
                        // its OVL1 handshake AND the 3-frame handoff
                        // protocol fully BEFORE the old stream is dropped,
                        // so AEAD state + nonce counters survive intact and
                        // queued frames continue flowing through the
                        // same `SessionTxRegistry` sender.
                        //
                        // If hot-standby refuses (no alt_uri, flap
                        // damping triggered, or URI parse failed), fall
                        // back to the legacy graceful-close path: just
                        // return from `run` and let the outbound connector
                        // re-dial (≈1 s gap).  Either way DPI sees the
                        // old TCP close + a new TCP+TLS handshake — a
                        // pattern indistinguishable from a browser tab
                        // ending and a new one starting.  No "rotation
                        // goodbye" frame is sent — that would itself be
                        // a fingerprint.
                        if session_rotation.is_due(now) {
                            if self.fire_hot_standby_trigger("rotation_deadline") {
                                // Make-before-break is now in flight in
                                // the background warm-probe task.  Re-
                                // arm the deadline so we don't re-fire
                                // before the swap completes (on success
                                // the runner sees `SwapStream` through
                                // `swap_rx` and rebinds the stream
                                // in-place — same session, new
                                // transport).  Picks a fresh random
                                // window from `[min, max]`.
                                session_rotation =
                                    crate::rotation_deadline::SessionRotationDeadline::compute(now);
                                continue;
                            }
                            // No alt_uri available (or flap-damped).
                            // Graceful close: just return from `run`.
                            // The caller cleans up.  Pre-Q.7 behaviour
                            // preserved bit-for-bit.
                            return;
                        }
                        // Evict expired RPC slots so they don't
                        // accumulate during quiet periods.
                        pending_responses.evict_expired(now);
                        // ── + 483.1: keepalive recalculation ─────────
                        // Closure samples globals only when check is due.
                        if let Some(new_interval) = battery_keepalive.maybe_recompute(now, || {
                            (
                                veil_util::local_battery_level(),
                                current_mobile_background_keepalive_factor(),
                            )
                        }) {
                            timers.update_keepalive_interval(new_interval, now);
                        }
                        continue;
                    }
                    NextInput::ReadClosed(error) => {
                        // stage (c.2) enhancement: the primary
                        // transport's read side closed (peer FIN / RST
                        // / kernel reset). This is the terminal
                        // degradation signal on Windows firewall-block
                        // scenarios where the one-way-block causes the
                        // peer's TCP to retransmit until it gives up
                        // then close. The `rx_stall` threshold may
                        // have been masked by retransmission flood, so
                        // it never fired.
                        //
                        // Primary is at EOF. We deliberately do NOT attempt
                        // a hot-standby swap here: `HandoffInit` would have
                        // to travel over the now-dead primary, so the swap
                        // can only fail (see `hot_standby_should_auto_fire`).
                        // `run()` returns below and the outbound reconnect
                        // path recovers the session — log WHY it terminated.
                        self.logger.info(
                            "session.primary_closed",
                            format!(
                                "peer_id={} primary transport read side closed error={} — reconnect path will recover",
                                hex_short(&self.peer_id),
                                error,
                            ),
                        );
                        return;
                    }
                    NextInput::WriterClosed => {
                        // Writer task exited — outbound writes are failing.
                        // This is the half-dead "outbound blocked, inbound
                        // alive" case hot-standby targets, so still fire the
                        // trigger: it attempts a swap to an alt transport
                        // before the session closes below.
                        self.logger.info(
                            "session.writer_closed",
                            format!(
                                "peer_id={} primary transport writer task exited — closing session",
                                hex_short(&self.peer_id),
                            ),
                        );
                        let _ = self.fire_hot_standby_trigger("writer_closed");
                        return;
                    }
                }
            }
            // Update last_rx after successfully reading the first byte of a frame.
            timers.note_frame_received(tokio::time::Instant::now());
            // stage (c.2): peer is responsive again, so a
            // future stall can re-fire the trigger.
            stall_trigger.clear();
            // Read the rest of the header (HEADER_SIZE - 1 remaining bytes).
            hdr_buf[0] = first_byte;
            match read_half.read_exact(&mut hdr_buf[1..]).await {
                Ok(_) => {}
                Err(e) => {
                    self.logger.warn(
                        "session.read_header_failed",
                        format!("peer_id={} error={e}", hex_short(&self.peer_id),),
                    );
                    break;
                }
            }

            let header = match decode_header_with_limit(&hdr_buf, self.max_frame_body) {
                Ok(h) => h,
                Err(e) => {
                    self.logger.warn(
                        "session.bad_header",
                        format!("peer_id={} error={e}", hex_short(&self.peer_id)),
                    );
                    self.record_violation("bad OVL1 header");
                    break;
                }
            };

            // ── Read body ────────────────────────────────────────────────────
            // Safety: `decode_header` already rejected body_len > MAX_FRAME_BODY
            // (16 MiB), so this allocation is bounded even in adversarial cases.
            //
            // bufpool refactor: the encrypted frame body buffer is
            // acquired from the global bufpool instead of a fresh
            // `Vec::with_capacity`.  Pool capacity is controlled by the
            // `VEIL_BUFPOOL_CAP` env var (default 64 buffers/bucket);
            // when set to 0 every acquire falls through to a direct heap
            // alloc (behaviourally identical to pre-pool code).  The
            // `Pooled` handle drops at the end of this scope iteration —
            // returning the buffer to the pool's cache OR freeing it to heap.
            let body_len = header.body_len as usize;
            let mut raw_body = veil_bufpool::global().acquire(body_len);
            raw_body.as_vec_mut().resize(body_len, 0);
            // slow-loris hardening: authenticated peer that
            // announced a body_len and then stops sending data should not be
            // able to pin a pool buffer + this task indefinitely. 30 s is
            // far above the 95-th percentile body-arrival latency on any
            // realistic link and bounds the worst-case memory exposure.
            if header.body_len > 0 {
                const BODY_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);
                match tokio::time::timeout(BODY_DEADLINE, read_half.read_exact(&mut raw_body[..]))
                    .await
                {
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => {
                        self.logger.warn(
                            "session.read_body_failed",
                            format!(
                                "peer_id={} body_len={} error={e}",
                                hex_short(&self.peer_id),
                                body_len,
                            ),
                        );
                        break;
                    }
                    Err(_) => {
                        self.record_violation("frame body read timeout (slow-loris)");
                        break;
                    }
                }
            }

            // ── Track bytes ──────────────────────────────────────────────────
            if let Some(m) = &self.metrics {
                m.add_transport_bytes_rx((veil_proto::header::HEADER_SIZE + raw_body.len()) as u64);
            }

            // Decrypt-in-place: plaintext is written into `raw_body`
            // (the pooled buffer that just held the ciphertext); zero
            // plaintext allocation on the common path.  Only the rare
            // rekey-grace fallback allocates (snapshotted copy of
            // original ciphertext, returned via `GracePlaintext`).
            let (body_owned, body_slice_from_raw): (Option<Vec<u8>>, bool) = {
                match self.decrypt_frame_body_in_place(
                    raw_body.as_vec_mut(),
                    header.family,
                    header.msg_type,
                    &rekey,
                    &mut rx_cipher_prev,
                ) {
                    std::ops::ControlFlow::Continue(
                        crate::runner::DecryptInPlaceOutcome::InPlace,
                    )
                    | std::ops::ControlFlow::Continue(
                        crate::runner::DecryptInPlaceOutcome::Passthrough,
                    ) => (None, true),
                    std::ops::ControlFlow::Continue(
                        crate::runner::DecryptInPlaceOutcome::GracePlaintext(pt),
                    ) => (Some(pt), false),
                    std::ops::ControlFlow::Break(()) => break,
                }
            };
            let body: &[u8] = if let Some(ref pt) = body_owned {
                pt.as_slice()
            } else if body_slice_from_raw {
                &raw_body[..]
            } else {
                unreachable!("decrypt outcome state machine produced inconsistent slot");
            };

            // ── Track RX bytes for rekey thresholds ──────────────────────────
            let rx_bytes = (veil_proto::header::HEADER_SIZE + body.len()) as u64;
            rekey.record_bytes(rx_bytes);
            mlkem_rekey.record_bytes(rx_bytes);

            // ── Intercept session rekey frames ───────────────────────────────
            if header.family == FrameFamily::Session as u8 {
                match SessionMsg::try_from(header.msg_type) {
                    Ok(SessionMsg::RekeyInit) => {
                        // Responder-path cipher swap + collision
                        // resolver + grace-buffer stash. Break on
                        // cipher / wire-write errors that should tear
                        // down the session.
                        match self.handle_rekey_init_arm(
                            body,
                            &mut rekey,
                            &mut rx_cipher_prev,
                            &wire_tx,
                            &mut write_error_count,
                        ) {
                            std::ops::ControlFlow::Continue(()) => continue,
                            std::ops::ControlFlow::Break(()) => return,
                        }
                    }
                    Ok(SessionMsg::RekeyAck) => {
                        // Break tears the session down when the peer's rekey
                        // ephemeral is non-contributory (downgrade attempt).
                        match self.handle_rekey_ack_arm(body, &mut rekey, &mut rx_cipher_prev) {
                            std::ops::ControlFlow::Continue(()) => continue,
                            std::ops::ControlFlow::Break(()) => return,
                        }
                    }
                    Ok(SessionMsg::RekeyKeptInit) => {
                        // Peer (lower node_id) told us they kept their own
                        // init and dropped ours — our pending init won't be
                        // ACK'd. Reset our FSM to Idle and push last_rekey_at
                        // forward so we don't immediately re-cross the
                        // threshold and re-collide.
                        self.handle_rekey_kept_init_arm(&mut rekey);
                        continue;
                    }
                    Ok(SessionMsg::MlKemRekeyEk) => {
                        match self.handle_mlkem_rekey_ek_arm(body, &wire_tx, &mut write_error_count)
                        {
                            std::ops::ControlFlow::Continue(()) => continue,
                            std::ops::ControlFlow::Break(()) => return,
                        }
                    }
                    Ok(SessionMsg::MlKemRekeyAck) => {
                        self.handle_mlkem_rekey_ack_arm(&mut mlkem_rekey);
                        continue;
                    }
                    Ok(SessionMsg::Ticket) => {
                        self.handle_ticket_arm(body);
                        continue;
                    }
                    // discardable padding frame — drop silently so
                    // the send-side coalescing of real+padding frames does not
                    // surface at the receiver. Body bytes are random and must
                    // never be parsed.
                    Ok(SessionMsg::Padding) => {
                        continue;
                    }
                    // stage (d) Task 3: hot-standby handoff protocol.
                    //
                    // HandoffInit — peer announces intent to migrate this
                    // session to a new underlying transport. We stash
                    // `(peer_id, nonce, rx_key)` in the shared handoff
                    // registry so the accept-side branch can bind
                    // an incoming warm socket's `HandoffAttach` back to
                    // this runner's `swap_rx`. Then echo the nonce in a
                    // `HandoffAck` so the peer knows the receiver side is
                    // ready.
                    Ok(SessionMsg::HandoffInit) => {
                        self.handle_handoff_init_arm(body, &mut pq);
                        continue;
                    }
                    // HandoffAck — initiator side receives peer's ready-to-swap
                    // signal. Forward the nonce to a waiting initiator task
                    // (warm-probe) via the one-shot channel it
                    // installed in `self.handoff_ack_tx` before sending
                    // `HandoffInit`. When no listener is set, the ack is
                    // silently logged — the peer side already stashed its
                    // pending handoff so this nonce is not lost; any retry
                    // from the initiator will time out cleanly via the
                    // registry's TTL.
                    Ok(SessionMsg::HandoffAck) => {
                        self.handle_handoff_ack_arm(body);
                        continue;
                    }
                    // HandoffAttach is the FIRST frame on a new warm socket
                    // not an in-session frame. Receiving it on an existing
                    // runner is protocol misuse — log + drop, no violation.
                    Ok(SessionMsg::HandoffAttach) => {
                        self.logger.warn(
                            "session.handoff.attach.misrouted",
                            format!("peer_id={} HandoffAttach on established session (must be new socket)",
                                hex_short(&self.peer_id)),
                        );
                        continue;
                    }
                    // Phase 5e: peer is informing us they've moved to a new
                    // transport URI (ephemeral-port rotation).  Decode +
                    // sig-verify the payload, then refresh the DHT
                    // transport-cache so subsequent reconnect attempts
                    // dial the new URI without a round-trip to the resolver.
                    Ok(SessionMsg::TransportMigrationNotify) => {
                        self.handle_transport_migration_notify_arm(body);
                        continue;
                    }
                    // Slice 5b of the PoW-Gated Rendezvous epic: requester
                    // is asking us to provision an ephemeral listener.
                    // Spawn a task that runs the controller; sends a
                    // signed response back on Granted, silently drops
                    // on Rejected (DoS-resistant).
                    Ok(SessionMsg::RequestEphemeralEndpoint) => {
                        self.handle_rendezvous_request_arm(body);
                        continue;
                    }
                    _ => {}
                }
            }

            // ── stage (c.2.2): acknowledge our TX leg is live ────────
            // KeepaliveAck arrives → peer received our Keepalive, so
            // the TX path is working. Clear the probe state and the
            // trigger-fired flag so a future stall can legitimately
            // re-fire. The dispatcher subsequently returns NoResponse
            // for KeepaliveAck, so this intercept is purely a side
            // channel for TX-health signalling.
            if header.family == FrameFamily::Control as u8
                && header.msg_type == ControlMsg::KeepaliveAck as u16
            {
                self.logger.debug(
                    "session.keepalive.ack_received",
                    format!(
                        "peer_id={} pending_was_set={}",
                        hex_short(&self.peer_id),
                        pending_keepalive_probe.is_armed()
                    ),
                );
                pending_keepalive_probe.clear();
                keepalive_probe_trigger.clear();
                keepalive_swap_attempts = 0;
            }

            // ── Intercept RPC responses before general dispatch ───────────────
            //
            // (475.6): V1 `FindNodeResponse` removed —
            // the discovery walker uses `FindNodeV2Response` and
            // `ResolveTransportResponse` +.
            if header.family == FrameFamily::Discovery as u8
                && matches!(
                    DiscoveryMsg::try_from(header.msg_type),
                    Ok(DiscoveryMsg::FindValueResponse)
                        | Ok(DiscoveryMsg::FindNodeV2Response)
                        | Ok(DiscoveryMsg::ResolveTransportResponse)
                )
                && let Some(tx) = pending_responses.take(header.request_id)
            {
                // Copy plaintext into an owned Vec for the oneshot receiver.
                // `body` is a slice borrowed from raw_body (which returns to
                // pool soon); the receiver needs an owned copy.
                let _ = tx.send(Some(body.to_vec()));
                continue; // consumed — do not dispatch
            }

            // ── Dispatch ─────────────────────────────────────────────────────
            let result = self.dispatcher.dispatch(&header, body, self.peer_id);

            // `process_dispatch_result` returns `true` when the runner
            // loop should break (session close due to cipher error / fatal
            // write error).
            if self.process_dispatch_result(
                result,
                &wire_tx,
                &mut rekey,
                &mut mlkem_rekey,
                &mut bp_signal,
                &mut write_error_count,
            ) {
                break;
            }
        }
        // ── b: writer task teardown ──────────────────────────
        // Loop exited (peer FIN, write error, ban, etc.). Drop wire_tx
        // so the writer task's `wire_rx.recv.await` returns None on
        // its next iteration; writer cleanly drains any pending bytes
        // shuts down its WriteHalf, and the JoinHandle resolves. We
        // await it so the WriteHalf is fully closed (peer sees clean
        // FIN) before run returns and the session-glue layer drops
        // its frame of reference. Best-effort: timeout if writer has
        // its own pathology, since we don't want to leak run callers.
        drop(wire_tx);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), writer_handle).await;
    }

    fn record_violation(&self, reason: &str) {
        self.logger.warn(
            "session.violation",
            format!("peer_id={} reason={reason}", hex_short(&self.peer_id)),
        );
        // Lock ordering: ban_list → violation_tracker (matches dispatcher convention).
        let mut ban_list = lock!(self.ban_list);
        let mut tracker = lock!(self.violation_tracker);
        tracker.record_with_log(
            self.peer_id,
            &mut ban_list,
            &*self.logger as &dyn veil_abuse::AbuseLogger,
        );
    }

    /// Epic 459 transport-swap plumbing.  Tears down the OLD writer
    /// task + channel and spawns a fresh one against the new transport,
    /// preserving ALL AEAD state (`tx_cipher` / `rx_cipher` /
    /// `session_id` stay on `self`).
    ///
    /// **Safety of the swap point**: caller (the `NextInput::SwapStream`
    /// arm in `run`) is **between frames** — no partial header has been
    /// consumed and the priority-queue flush has already completed.
    /// In-flight bytes cannot tear across transports.
    ///
    /// The peer's side must have already swapped its own stream at
    /// the matching protocol moment; cross-peer coordination is the
    /// responsibility of the controller (Epic 459 handoff FSM).
    ///
    /// Returns the new `(read_half, wire_tx, writer_handle)` tuple
    /// — caller rebinds its three locals.
    async fn swap_transport_plumbing(
        &self,
        new_stream: veil_transport::BoxIoStream,
        old_wire_tx: mpsc::Sender<veil_bufpool::PooledShared>,
        mut old_writer_handle: tokio::task::JoinHandle<()>,
    ) -> (
        tokio::io::ReadHalf<veil_transport::BoxIoStream>,
        mpsc::Sender<veil_bufpool::PooledShared>,
        tokio::task::JoinHandle<()>,
    ) {
        self.logger.info(
            "session.transport_swapped",
            format!(
                "peer_id={} session preserved across transport handover",
                hex_short(&self.peer_id)
            ),
        );
        // Drop wire_tx first → writer's `wire_rx.recv.await` returns
        // None → writer cleanly exits → JoinHandle resolves.
        drop(old_wire_tx);
        let _ = (&mut old_writer_handle).await;
        let (new_read, new_write) = tokio::io::split(new_stream);
        let (new_tx, new_rx) = mpsc::channel::<veil_bufpool::PooledShared>(WIRE_CHANNEL_CAPACITY);
        let new_writer_handle = spawn_writer_task(
            new_write,
            new_rx,
            self.metrics.clone(),
            Arc::clone(&self.logger),
            hex_short(&self.peer_id),
        );
        (new_read, new_tx, new_writer_handle)
    }

    /// Handle the six DispatchResult variants emitted by
    /// `FrameDispatcher::dispatch`.
    ///
    /// Returns `true` if the caller's run-loop should `break`
    /// (cipher error during response encryption, or push_wire fatal
    /// error).  Returns `false` otherwise — caller continues the loop.
    fn process_dispatch_result(
        &mut self,
        result: DispatchResult,
        wire_tx: &mpsc::Sender<veil_bufpool::PooledShared>,
        rekey: &mut crate::rekey_context::RekeyContext,
        mlkem_rekey: &mut crate::mlkem_rekey_context::MlKemRekeyContext,
        bp_signal: &mut crate::backpressure_signal::BackpressureSignal,
        write_error_count: &mut crate::write_error_tracker::WriteErrorTracker,
    ) -> bool {
        match result {
            DispatchResult::Response(resp_bytes) => {
                // Never advance the implicit AEAD nonce unless the encrypted
                // frame has a writer slot. Dropping after encryption permanently
                // desynchronises every later frame on this session.
                if wire_tx.capacity() == 0 {
                    return false;
                }
                let planned_wire_len = if self.crypto.tx_cipher.is_some() {
                    match encrypted_wire_len(resp_bytes.len()) {
                        Some(n) => n,
                        None => return true,
                    }
                } else {
                    resp_bytes.len()
                };
                // Apply bandwidth limiting before encryption for the same nonce
                // safety reason as the pq-drain path.
                if !self.dispatcher.allow_outbound_bandwidth(planned_wire_len) {
                    return false;
                }
                // Capture the plaintext response before any encryption.
                self.dispatcher.capture_outbound(self.peer_id, &resp_bytes);
                // Encrypt the response body if the session uses encryption.
                let wire_bytes = if let Some(cipher) = self.crypto.tx_cipher.as_mut() {
                    match apply_tx_cipher(&resp_bytes, cipher) {
                        Some(enc) => enc,
                        None => return true, // cipher/header error — close session
                    }
                } else {
                    veil_bufpool::pooled_shared_from_vec(resp_bytes)
                };

                let resp_len = wire_bytes.len() as u64;
                if let Some(m) = &self.metrics {
                    m.add_transport_bytes_tx(resp_len);
                }
                rekey.record_bytes(resp_len);
                mlkem_rekey.record_bytes(resp_len);
                if Self::push_wire(wire_tx, wire_bytes, &self.metrics).is_err() {
                    self.on_primary_write_error(write_error_count);
                    return true;
                }
            }
            DispatchResult::NoResponse => {}
            DispatchResult::Violation(reason) => {
                self.record_violation(&reason);
                // Do NOT close the session on a single violation —
                // the ban list will handle repeated offenders.
            }
            DispatchResult::RateLimited => {
                // Send a Backpressure signal at most once per cooldown.
                // Excess frames are silently dropped — no violation, no ban.
                log::debug!(
                    "LIMIT rate_limited: inbound frame DROPPED from peer {} \
                     (over capacity / relay congestion-shed)",
                    hex_short(&self.peer_id),
                );
                let now = std::time::Instant::now();
                if bp_signal.try_arm(now) {
                    // Backpressure is an expected congestion signal on busy
                    // streams.  Keep the signal itself, but do not WARN-flood
                    // embedded/mobile hosts; stdout/logcat backpressure can
                    // become the bottleneck under high-rate synthetic tests.
                    log::debug!(
                        "LIMIT rate_limited: backpressure ARMED -> peer {} \
                         — sustained inbound exceeds capacity",
                        hex_short(&self.peer_id),
                    );
                    // Fire-and-forget means "skip before encryption" when the
                    // writer is saturated — never seal then drop, which burns an
                    // implicit AEAD nonce and makes the peer close the session.
                    if wire_tx.capacity() == 0 {
                        return false;
                    }
                    let bp_hdr = veil_proto::header::FrameHeader::new(
                        veil_proto::family::FrameFamily::Control as u8,
                        veil_proto::family::ControlMsg::Backpressure as u16,
                    );
                    let bp_frame = veil_proto::codec::encode_header(&bp_hdr).to_vec();
                    let wire_bytes = if let Some(cipher) = self.crypto.tx_cipher.as_mut() {
                        match apply_tx_cipher(&bp_frame, cipher) {
                            Some(enc) => enc,
                            None => return true,
                        }
                    } else {
                        veil_bufpool::pooled_shared_from_vec(bp_frame)
                    };
                    // backpressure signal is fire-and-forget;
                    // a stalled write here is a strong indication
                    // the peer's recv buffer is itself full — ironic
                    // because that's the case the BP signal exists to
                    // mitigate.  Use the timeout-wrapped write so a
                    // stalled BP send doesn't pin the entire runner;
                    // metric increments either way (visible "BP signal
                    // skipped because peer was already saturated").
                    let _ = Self::push_wire(wire_tx, wire_bytes, &self.metrics);
                }
            }
            DispatchResult::NotHandled => {
                // Session-layer frames (e.g. handshake replay) are silently
                // ignored post-handshake.
            }
            DispatchResult::SolvePow(challenge) => {
                // Spawn a blocking task to solve the PoW puzzle, then route the
                // PowResponse back toward the acceptor.
                use veil_proto::{
                    budget::MAX_POW_ACTIVE_DIFFICULTY_SUM, family::RoutingMsg,
                    routing::PowResponsePayload,
                };
                use veil_routing::pow::solve_pow;
                // Inline helper: encode a FAMILY_ROUTING frame.
                // (Previously `crate::node::dispatcher::encode_routing_frame`;
                // inlined here to avoid veil-session→veilcore dep.)
                fn encode_routing_frame(msg: RoutingMsg, body: &[u8]) -> Vec<u8> {
                    use veil_proto::codec::encode_header;
                    use veil_proto::family::FrameFamily;
                    use veil_proto::header::{FrameHeader, HEADER_SIZE};
                    let mut hdr = FrameHeader::new(FrameFamily::Routing as u8, msg as u16);
                    hdr.body_len = body.len() as u32;
                    let mut out = Vec::with_capacity(HEADER_SIZE + body.len());
                    out.extend_from_slice(&encode_header(&hdr));
                    out.extend_from_slice(body);
                    out
                }

                // Global cap on concurrent blocking solver tasks.
                let permit = match self.dispatcher.pow_solver_semaphore().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        self.dispatcher.logger().warn(
                            "session.solve_pow",
                            "solver semaphore full — dropping challenge",
                        );
                        return false;
                    }
                };

                // Cap total difficulty in flight.  Safety: fetch_add
                // returns the *previous* value, so `prev + difficulty`
                // is the new value after the add.  This check is
                // correct even under concurrency: each thread atomically
                // reserves its slice of the budget and then immediately
                // verifies it didn't exceed the cap.
                let difficulty = u64::from(challenge.difficulty);
                let budget = self.dispatcher.pow_active_difficulty();
                let prev = budget.fetch_add(difficulty, std::sync::atomic::Ordering::Relaxed);
                if prev + difficulty > MAX_POW_ACTIVE_DIFFICULTY_SUM {
                    budget.fetch_sub(difficulty, std::sync::atomic::Ordering::Relaxed);
                    self.dispatcher.logger().warn(
                        "session.solve_pow",
                        format!(
                            "difficulty budget exceeded (in_flight={prev}, requested={difficulty}) — dropping challenge"
                        ),
                    );
                    return false;
                }
                // RAII guard — decrements budget on drop regardless of
                // how the task exits (early return, panic, cancellation).
                let budget_guard = BudgetGuard {
                    budget: Arc::clone(&budget),
                    difficulty,
                };

                let dispatcher = Arc::clone(&self.dispatcher);
                let sender_peer_id = self.peer_id;
                tokio::spawn(async move {
                    // permit released when task ends.
                    let _permit = permit;
                    let _budget_guard = budget_guard;
                    let rid = challenge.requester_node_id;
                    let cn = challenge.challenge_nonce;
                    let acceptor = challenge.acceptor_node_id;
                    let diff_u8 = challenge.difficulty;
                    let solution =
                        match tokio::task::spawn_blocking(move || solve_pow(&rid, &cn, diff_u8))
                            .await
                        {
                            Ok(s) => s,
                            Err(e) => {
                                dispatcher.logger().warn(
                                    "session.solve_pow",
                                    format!("spawn_blocking panicked: {e}"),
                                );
                                // do NOT send a zero-solution PowResponse —
                                // the acceptor would treat it as a Violation.
                                // Simply drop the challenge.
                                return;
                            }
                        };

                    let resp = PowResponsePayload {
                        requester_node_id: rid,
                        acceptor_node_id: acceptor,
                        challenge_nonce: cn,
                        solution_nonce: solution,
                    };
                    let frame = encode_routing_frame(RoutingMsg::PowResponse, &resp.encode());
                    if let Some(reg) = dispatcher.session_tx_registry() {
                        // DEADLOCK FIX (audit 2026-05-29): snapshot the
                        // route-cache fallback hop BEFORE taking the
                        // session_tx_registry write lock, matching the
                        // canonical route_cache→registry order in
                        // routing.rs.  Holding registry-write while
                        // acquiring route_cache-read (the prior order)
                        // could deadlock against a thread taking them in
                        // canonical order.
                        let next_hop = rlock!(dispatcher.route_cache()).lookup(&acceptor);
                        // Read lock: send_to/get_sender take &self (tx_registry's
                        // send-path contract), so concurrent PoW responses to
                        // different acceptors run in parallel. (audit cycle-8 F5.)
                        let guard = rlock!(reg);
                        // Try direct session to acceptor first; fall back
                        // via route cache then via the peer who sent
                        // us the challenge.
                        if !guard.send_to(
                            &acceptor,
                            veil_proto::header::priority::INTERACTIVE,
                            frame.clone(),
                        ) {
                            let dest = next_hop.unwrap_or(sender_peer_id);
                            guard.send_to(&dest, veil_proto::header::priority::INTERACTIVE, frame);
                        }
                    }
                });
            }
        }
        false
    }
}

use veil_util::hex_short;

// ── tests ─────────────────────────────────────────────────────────────────────
//
// NB: there is no separate `runner_tests.rs` file — an earlier comment here
// claimed the test module was extracted to a sibling file via `#[path]`, but no
// such file or attribute exists. Runner unit tests live inline in `#[cfg(test)]`
// modules in this file (e.g. `m1_empty_frame_aead_tests`) and in the
// `veil-session-integration-tests` crate.

#[cfg(test)]
mod m1_empty_frame_aead_tests {
    use super::*;
    use veil_proto::header::HEADER_SIZE;

    /// cycle-7 M1: a header-only control frame (body_len == 0) MUST be
    /// AEAD-sealed when a cipher is present — it grows by exactly the AEAD tag
    /// and decodes/opens back to empty plaintext — rather than being returned
    /// verbatim and unauthenticated (the previous behaviour that let an on-path
    /// attacker forge Keepalive / RekeyKeptInit / MlKemRekeyAck on a
    /// plaintext-TCP link).
    #[test]
    fn empty_control_frame_is_sealed_not_passed_through() {
        const AEAD_OVERHEAD: usize = veil_crypto::session_cipher::AEAD_OVERHEAD;
        let key = [0x11u8; 32];
        let mut tx = SessionCipher::new(&key, true);

        // A header-only frame: full header, zero body.
        let hdr = FrameHeader::new(0u8, 0u16);
        let frame = encode_header(&hdr).to_vec();
        assert_eq!(frame.len(), HEADER_SIZE);

        let sealed = apply_tx_cipher(&frame, &mut tx).expect("empty frame must seal");
        let bytes = sealed.as_slice();
        assert_eq!(
            bytes.len(),
            HEADER_SIZE + AEAD_OVERHEAD,
            "empty control frame must carry a 16-byte AEAD tag, not pass through verbatim"
        );

        let out_hdr = decode_header(bytes).expect("decode sealed header");
        assert_eq!(
            out_hdr.body_len as usize, AEAD_OVERHEAD,
            "body_len must reflect the AEAD tag length"
        );

        // Round-trip: a peer cipher with the same key opens it to empty plaintext.
        let mut rx = SessionCipher::new(&key, true);
        let aad = frame_aad(out_hdr.family, out_hdr.msg_type);
        let pt = rx
            .open(&bytes[HEADER_SIZE..], &aad)
            .expect("sealed empty frame must open");
        assert!(pt.is_empty(), "sealed empty frame opens to empty plaintext");
    }

    #[test]
    fn several_encrypted_frames_share_one_padding_bucket_and_stay_parseable() {
        let padding_was_enabled = padding_enabled();
        set_padding_enabled(true);
        let key = [0x22u8; 32];
        let mut tx = SessionCipher::new(&key, true);
        let bodies = [vec![0xA1; 300], vec![0xB2; 300], vec![0xC3; 300]];
        let mut real_batch = Vec::new();

        for (i, body) in bodies.iter().enumerate() {
            let mut hdr = FrameHeader::new(FrameFamily::Control as u8, i as u16 + 1);
            hdr.body_len = body.len() as u32;
            let mut frame = encode_header(&hdr).to_vec();
            frame.extend_from_slice(body);
            let sealed = apply_tx_cipher(&frame, &mut tx).expect("seal real frame");
            real_batch.extend_from_slice(&sealed);
        }

        let wire = coalesce_with_padding(&real_batch, Some(&mut tx));
        assert_eq!(wire.len(), 1300, "three small real frames share one bucket");

        let mut rx = SessionCipher::new(&key, true);
        let mut cursor = 0usize;
        let mut opened = Vec::new();
        while cursor < wire.len() {
            let hdr = decode_header(&wire[cursor..]).expect("decode concatenated header");
            let frame_len = HEADER_SIZE + hdr.body_len as usize;
            let body_start = cursor + HEADER_SIZE;
            let body_end = cursor + frame_len;
            let aad = frame_aad(hdr.family, hdr.msg_type);
            let plaintext = rx
                .open(&wire[body_start..body_end], &aad)
                .expect("open concatenated frame in cipher order");
            opened.push((hdr.family, hdr.msg_type, plaintext));
            cursor = body_end;
        }

        assert_eq!(opened.len(), 4, "three real frames plus one padding frame");
        for (i, expected) in bodies.iter().enumerate() {
            assert_eq!(opened[i].2, *expected);
        }
        assert_eq!(opened[3].0, FrameFamily::Session as u8);
        assert_eq!(opened[3].1, SessionMsg::Padding as u16);
        set_padding_enabled(padding_was_enabled);
    }
}

#[cfg(test)]
mod reeval_teardown_tests {
    use super::*;
    use std::time::Duration;

    const TIMEOUT: Duration = Duration::from_secs(10);
    const CEILING: u32 = KEEPALIVE_SWAP_ATTEMPT_CEILING;

    /// (a) KeepaliveAck-before-2x: failover not exhausted → no teardown.
    #[test]
    fn ack_before_2x_no_teardown() {
        assert!(!should_reeval_teardown(
            TIMEOUT, // probe_age stale
            TIMEOUT, 1, // swap_attempts < ceiling (2)
            CEILING, TIMEOUT, // genuine stale
            true,    // hot_standby_ok
        ));
    }

    /// (b) Fresh genuine RX protects even with attempts past ceiling + no
    /// hot standby.
    #[test]
    fn fresh_genuine_rx_no_teardown() {
        assert!(!should_reeval_teardown(
            TIMEOUT,
            TIMEOUT,
            5,
            CEILING,
            TIMEOUT / 2, // genuine NOT stale
            false,
        ));
    }

    /// (c) THE core MUST-FIX #1 case: a multi-transport / learned-alt_uri
    /// relay keeps hot_standby_ok == true forever, yet the ceiling reaps the
    /// zombie once swap_attempts == ceiling.
    #[test]
    fn multi_transport_learned_alt_uri_reaps_at_ceiling() {
        assert!(should_reeval_teardown(
            TIMEOUT, TIMEOUT, CEILING, // == ceiling
            CEILING, TIMEOUT, // genuine stale
            true,    // hot_standby_ok STAYS true — ceiling overrides
        ));
    }

    /// (d) Probe not yet stale → no teardown.
    #[test]
    fn probe_not_stale_no_teardown() {
        assert!(!should_reeval_teardown(
            TIMEOUT / 2, // probe_age < timeout
            TIMEOUT,
            CEILING,
            CEILING,
            TIMEOUT,
            false,
        ));
    }

    /// (e) Zero probe_timeout (keepalive disabled) → never reap.
    #[test]
    fn zero_timeout_no_teardown() {
        assert!(!should_reeval_teardown(
            TIMEOUT,
            Duration::ZERO,
            CEILING,
            CEILING,
            TIMEOUT,
            false,
        ));
    }

    /// (f) Original M5 no-warm-probe case: no hot standby, first re-eval,
    /// both stale → reap immediately.
    #[test]
    fn no_failover_first_reeval() {
        assert!(should_reeval_teardown(
            TIMEOUT, TIMEOUT, 0, // swap_attempts 0
            CEILING, TIMEOUT, false, // no warm probe
        ));
    }

    /// (g) One-directional TX wedge: genuine RX perfectly fresh (peer keeps
    /// sending) but our keepalives have gone unacked for
    /// TX_WEDGE_PROBE_MULTIPLE whole windows → fresh RX must NOT veto the
    /// reap.
    #[test]
    fn tx_wedge_reaps_despite_fresh_genuine_rx() {
        assert!(should_reeval_teardown(
            TIMEOUT * TX_WEDGE_PROBE_MULTIPLE,
            TIMEOUT,
            CEILING,
            CEILING,
            Duration::ZERO, // genuine RX fresh — inbound alive
            false,
        ));
    }

    /// (h) Below the wedge multiple the fresh-RX veto still holds — a probe
    /// stale for only 2 windows with live inbound is NOT yet proof of a
    /// wedge (ack may be riding a loss-retransmit).
    #[test]
    fn tx_wedge_below_multiple_fresh_rx_still_protects() {
        assert!(!should_reeval_teardown(
            TIMEOUT * (TX_WEDGE_PROBE_MULTIPLE - 1),
            TIMEOUT,
            CEILING,
            CEILING,
            Duration::ZERO,
            false,
        ));
    }

    /// (i) TX wedge with failover still available (hot-standby swaps below
    /// ceiling) → no reap; the swap path gets its chance first.
    #[test]
    fn tx_wedge_with_failover_no_teardown() {
        assert!(!should_reeval_teardown(
            TIMEOUT * TX_WEDGE_PROBE_MULTIPLE,
            TIMEOUT,
            1, // swap_attempts < ceiling
            CEILING,
            Duration::ZERO,
            true, // hot_standby_ok
        ));
    }
}
