//! IPC server: accepts local application connections over a Unix-domain
//! socket OR a TCP-loopback port, performs the APP_HELLO
//! handshake, and manages per-client state.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use crate::frame_io::{encode_ipc_frame, read_frame, write_frame_stream, write_frame_wh};
use crate::handlers::anycast::{
    handle_anycast_advertise, handle_anycast_report_failure, handle_anycast_resolve,
    handle_anycast_withdraw, handle_transport_hint_query,
};
use crate::handlers::bind::handle_bind;
use crate::handlers::mailbox::{
    handle_mailbox_ack, handle_mailbox_fetch, handle_mailbox_open, handle_mailbox_put,
    handle_mailbox_seal,
};
use crate::handlers::mobile::{
    handle_network_changed, handle_set_mobile_background_mode, handle_set_push_envelope,
    handle_set_wake_hmac_envelope,
};
use crate::handlers::outbox::{handle_outbox_ack, handle_outbox_find_missing, handle_outbox_put};
use crate::handlers::queries::{
    handle_get_mobile_status, handle_get_node_identity, handle_get_peers,
    handle_join_bootstrap_uri, handle_lookup_rendezvous_replicas,
};
use crate::handlers::send::{IpcSendContext, handle_ipc_send, handle_rt_send};
use crate::handlers::stream::handle_stream_open;
#[cfg(windows)]
use crate::path::IPC_PIPE_FILENAME;
use crate::path::{IPC_PORT_FILENAME, IPC_TOKEN_FILENAME, IpcEndpoint};
use crate::transport::{self, IpcStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, watch};

use crate::IpcMetrics;
use crate::streams::IpcStreamTable;
use veil_abuse::rate_limiter::{RateLimiter, TokenBucket};
use veil_app::registry::{AppEndpointRegistry, AppMessage, EndpointHandle};
use veil_proto::{
    AppDeliverPayload, AppIpcHelloErrPayload, AppIpcHelloOkPayload, AppIpcHelloPayload,
    AppUnbindPayload, CLIENT_MAX_VERSION, CLIENT_MIN_VERSION, FrameFamily, FrameHeader,
    IPC_PROTOCOL_VERSION, LocalAppMsg, StreamClosePayload, StreamDataPayload, StreamWindowPayload,
    codec, ipc_hello_err, ipc_send_err,
};
use veil_types::FrameBroadcaster;

// ── IpcClientState ──────────────────────────────────────────────────────────

/// Per-connection state for an authenticated IPC client.
///
/// Holds endpoint RAII handles. When a receiver is added via `add_endpoint`
/// a forwarder task is spawned that converts `AppMessage` → `APP_DELIVER` frames
/// and pushes them to the shared `delivery_tx` channel. The main client loop
/// reads from `delivery_rx` and writes the frames to the IPC socket.
///
/// Dropping this struct drops all `EndpointHandle`s → auto-unbinds all endpoints.
/// Per-app socket files are also removed on drop.
///
/// token-bucket rate limit for
/// read-only IPC queries. 10 queries per second sustained, 30-token
/// burst — generous for any legitimate UI (e.g. peer-debug screen
/// polling once a second) but cuts an exfiltration loop down from
/// "as fast as the daemon can reply" to a survey rate.
const IPC_QUERY_REFILL_PER_SEC: f32 = 10.0;
const IPC_QUERY_BURST: u32 = 30;
/// audit cycle-6 (A9): per-client `MailboxPut` rate. More generous than the
/// read-query bucket — message delivery is the primary data path for offline
/// mailbox — but still caps a runaway local process. The backend's own
/// per-receiver limit (60/min) handles per-recipient fairness; this bounds the
/// aggregate per-CLIENT call rate so receiver-id rotation can't bypass it.
const IPC_PUT_REFILL_PER_SEC: f32 = 50.0;
const IPC_PUT_BURST: u32 = 200;

/// Byte-budgeted, clone-able sender for a client's veil→IPC delivery queue.
///
/// The underlying mpsc is bounded by frame COUNT (`DELIVERY_CHANNEL_CAP`), but a
/// single reassembled delivery can be many MiB (a relay-chunked transfer joins
/// up to `MAX_REASSEMBLY_BYTES` before the app reads it), so a full count-queue
/// could pin gigabytes against a slow / non-reading client. This wrapper also
/// caps total IN-FLIGHT BYTES: `try_send` refuses (reported as `Full`, i.e. the
/// frame is dropped + counted exactly like a count-full queue) once the queued
/// bytes would exceed `max_bytes`. The socket-writer drain decrements the shared
/// counter as each frame is pulled off the queue.
#[derive(Clone)]
pub(crate) struct DeliveryQueueTx {
    tx: mpsc::Sender<veil_bufpool::PooledShared>,
    inflight_bytes: Arc<AtomicUsize>,
    max_bytes: usize,
}

impl DeliveryQueueTx {
    /// Enqueue a frame, refusing once the per-client in-flight byte budget would
    /// be exceeded (returns `Full(frame)`, matching the count-cap behaviour).
    pub(crate) fn try_send(
        &self,
        frame: veil_bufpool::PooledShared,
    ) -> Result<(), mpsc::error::TrySendError<veil_bufpool::PooledShared>> {
        let len = frame.len();
        // Reserve the byte budget with a CAS loop (no transient over-count), then
        // roll back if the bounded channel itself rejects the frame.
        let mut cur = self.inflight_bytes.load(Ordering::Acquire);
        loop {
            if cur.saturating_add(len) > self.max_bytes {
                return Err(mpsc::error::TrySendError::Full(frame));
            }
            match self.inflight_bytes.compare_exchange_weak(
                cur,
                cur + len,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(actual) => cur = actual,
            }
        }
        match self.tx.try_send(frame) {
            Ok(()) => Ok(()),
            Err(e) => {
                self.inflight_bytes.fetch_sub(len, Ordering::AcqRel);
                Err(e)
            }
        }
    }
}

/// Test-only: wrap a raw sender with an effectively-unbounded byte budget so
/// existing tests that build a bare `mpsc::channel` pass straight through the
/// `impl Into<DeliveryQueueTx>` parameters without each call site changing.
#[cfg(test)]
impl From<mpsc::Sender<veil_bufpool::PooledShared>> for DeliveryQueueTx {
    fn from(tx: mpsc::Sender<veil_bufpool::PooledShared>) -> Self {
        Self {
            tx,
            inflight_bytes: Arc::new(AtomicUsize::new(0)),
            max_bytes: usize::MAX,
        }
    }
}

/// Create a byte-budgeted delivery queue: the clone-able sender, the receiver
/// the socket-writer loop drains, and the shared in-flight-bytes counter the
/// drain decrements (by each frame's length) after pulling a frame off.
fn delivery_queue(
    count_cap: usize,
    max_bytes: usize,
) -> (
    DeliveryQueueTx,
    mpsc::Receiver<veil_bufpool::PooledShared>,
    Arc<AtomicUsize>,
) {
    let (tx, rx) = mpsc::channel::<veil_bufpool::PooledShared>(count_cap);
    let inflight = Arc::new(AtomicUsize::new(0));
    (
        DeliveryQueueTx {
            tx,
            inflight_bytes: Arc::clone(&inflight),
            max_bytes,
        },
        rx,
        inflight,
    )
}

/// Wire-routing for an acceptor-side stream whose opener is on a REMOTE node.
/// Lets the acceptor's outbound STREAM_DATA / STREAM_CLOSE be forwarded to the
/// opener's node as wire AppData / AppClose (the opener's node already has the
/// inbound bridge to deliver them to its IPC client).
#[derive(Clone, Copy)]
pub(crate) struct AcceptorRemoteRoute {
    /// The opener's node_id — destination for our outbound wire frames.
    opener_node_id: [u8; 32],
    /// Bound endpoint's app_id (echoed in the wire AppData / AppClose).
    app_id: [u8; 32],
    /// Bound endpoint id.
    endpoint_id: u32,
}

pub struct IpcClientState {
    /// RAII guards paired with optional per-app socket paths.
    handles: Vec<(EndpointHandle, Option<PathBuf>)>,
    /// Sender side of the delivery channel (cloned per forwarder task).
    delivery_tx: DeliveryQueueTx,
    /// Metrics handle for counting dropped IPC frames.
    metrics: Option<Arc<dyn IpcMetrics>>,
    /// Local node identity, needed by forwarder to encode APP_DELIVER frames.
    node_id: [u8; 32],
    /// Per-connection random token issued in `APP_HELLO_OK`. Used to derive
    /// ephemeral `app_id`s that are unique to this connection.
    client_token: [u8; 16],
    /// Cumulative count of locally-originated streams opened over this
    /// IPC session. Capped at `MAX_IPC_STREAMS_PER_CLIENT` to prevent a
    /// single client from exhausting the global `MAX_TOTAL_STREAMS` quota
    ///. Counter does not decrement on close —
    /// budget resets only on reconnect. 256 is well above any reasonable
    /// app's needs while still bounding worst-case impact.
    streams_opened: u32,
    /// cumulative bind decode-failure count.
    /// A buggy or hostile local app spamming malformed `APP_BIND` frames
    /// previously consumed a full IPC-write per attempt with no upper
    /// bound — bounded here at `MAX_BIND_DECODE_FAILURES` for the
    /// connection's lifetime. Once exceeded, the IPC session is
    /// terminated by the caller (the handler returns an `io::Error`
    /// after writing the final `AppBindErr`).
    bind_decode_failures: u32,
    /// Streams this client opened (this client is the **opener / A side**).
    ///
    /// Populated by `handle_stream_open` after the daemon writes
    /// `STREAM_OPEN_OK` back to the SDK, cleared when this client sends
    /// `STREAM_CLOSE`.  Cross-client hijack is prevented downstream by
    /// checking that incoming `STREAM_DATA`/`STREAM_CLOSE`/`STREAM_WINDOW`
    /// frames reference a `stream_id` that is in either this set or
    /// `owned_streams_acceptor` — without such a check, any local IPC client
    /// could push bytes into / close another client's stream by simply
    /// guessing the `stream_id`.
    owned_streams_opener: std::collections::HashSet<u32>,
    /// Streams this client is the acceptor (this client is the **B
    /// side**) of, populated by the per-endpoint forwarder task when it
    /// translates an `AppMessage::StreamOpen` into a `STREAM_OPEN_INBOUND`
    /// IPC frame, cleared when the matching `AppMessage::StreamClose`
    /// arrives.  Held behind `Arc<Mutex<_>>` because the forwarder runs
    /// in a separate task from the IPC read loop that updates
    /// `owned_streams_opener`.  Pre-fix the acceptor never claimed
    /// ownership at all, so every `STREAM_DATA` frame from the acceptor
    /// SDK was silently dropped by the server — turning a documented
    /// bidirectional stream into a one-way pipe (HIGH-1, audit batch
    /// 2026-05-23).
    owned_streams_acceptor: Arc<std::sync::Mutex<std::collections::HashSet<u32>>>,
    /// For acceptor streams whose OPENER lives on a REMOTE node, the wire route
    /// to send this client's outbound STREAM_DATA / STREAM_CLOSE back to the
    /// opener as wire AppData / AppClose. Populated by the per-endpoint
    /// forwarder alongside `owned_streams_acceptor` when the inbound open's
    /// `src_node_id` is NOT our own; empty for same-node (local) acceptor
    /// streams, which route through the local stream table. Without it a
    /// cross-node bidirectional stream is a one-way pipe — the acceptor's
    /// replies hit `route_data_from_b`'s local-only lookup and are silently
    /// dropped (the cross-node analogue of the same-node HIGH-1 fix above).
    owned_streams_acceptor_routes:
        Arc<std::sync::Mutex<std::collections::HashMap<u32, AcceptorRemoteRoute>>>,
    /// rolling token-bucket rate
    /// limiter for the cheap-but-info-leaky read-only IPC queries
    /// (GetPeers, GetNodeIdentity, GetMobileStatus, JoinBootstrapUri).
    /// Without it, a sandboxed-but-IPC-capable adversary process
    /// could spam GetPeers in a tight loop and exfiltrate a high-
    /// resolution peer-graph snapshot stream. Bucket fills at
    /// `IPC_QUERY_REFILL_PER_SEC` and caps at `IPC_QUERY_BURST`;
    /// `last_refill` ticks via `Instant::now`.
    query_tokens: f32,
    query_last_refill: std::time::Instant,
    /// audit cycle-6 (A9): dedicated per-client token bucket for `MailboxPut`.
    /// `handle_mailbox_fetch` is already gated by `allow_query`, but `MailboxPut`
    /// was not rate-limited per IPC client — a local adversarial process could
    /// spam `MailboxPut` across many distinct receiver_ids, driving the backend
    /// mutex + quota-scan path on every call (the backend's own limit is
    /// per-RECEIVER, so per-receiver-rotation bypasses it). Separate from the
    /// read-query bucket so bulk message delivery does not starve read queries
    /// and vice-versa. Fills at `IPC_PUT_REFILL_PER_SEC`, caps at `IPC_PUT_BURST`.
    put_tokens: f32,
    put_last_refill: std::time::Instant,
}

impl IpcClientState {
    fn new(
        delivery_tx: impl Into<DeliveryQueueTx>,
        node_id: [u8; 32],
        client_token: [u8; 16],
        metrics: Option<Arc<dyn IpcMetrics>>,
    ) -> Self {
        Self {
            handles: Vec::new(),
            delivery_tx: delivery_tx.into(),
            metrics,
            node_id,
            client_token,
            streams_opened: 0,
            bind_decode_failures: 0,
            owned_streams_opener: std::collections::HashSet::new(),
            owned_streams_acceptor: Arc::new(std::sync::Mutex::new(
                std::collections::HashSet::new(),
            )),
            owned_streams_acceptor_routes: Arc::new(std::sync::Mutex::new(
                std::collections::HashMap::new(),
            )),
            query_tokens: IPC_QUERY_BURST as f32,
            query_last_refill: std::time::Instant::now(),
            put_tokens: IPC_PUT_BURST as f32,
            put_last_refill: std::time::Instant::now(),
        }
    }

    /// rate-limit a read-only IPC
    /// query (GetPeers / GetNodeIdentity / GetMobileStatus /
    /// JoinBootstrapUri). Returns `true` if the request is
    /// allowed; the caller then proceeds normally. Returns
    /// `false` if the bucket is empty; the caller MUST silently
    /// drop the request (no reply frame) so the rate limit isn't
    /// itself a probing oracle.
    pub(super) fn allow_query(&mut self) -> bool {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.query_last_refill).as_secs_f32();
        self.query_last_refill = now;
        self.query_tokens =
            (self.query_tokens + elapsed * IPC_QUERY_REFILL_PER_SEC).min(IPC_QUERY_BURST as f32);
        if self.query_tokens >= 1.0 {
            self.query_tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// audit cycle-6 (A9): per-client token-bucket gate for `MailboxPut`.
    /// Returns `true` if a put is allowed (consuming one token), `false` when
    /// the bucket is empty (the caller should reply `MailboxPutStatus::RateLimited`
    /// without touching the backend).
    pub(super) fn allow_put(&mut self) -> bool {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.put_last_refill).as_secs_f32();
        self.put_last_refill = now;
        self.put_tokens =
            (self.put_tokens + elapsed * IPC_PUT_REFILL_PER_SEC).min(IPC_PUT_BURST as f32);
        if self.put_tokens >= 1.0 {
            self.put_tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Claim a stream_id as **opener-side** (this client was the one that
    /// sent `STREAM_OPEN`).  Subsequent `STREAM_DATA`/`STREAM_CLOSE`/
    /// `STREAM_WINDOW` frames bearing the same id can then be authorised
    /// and routed via `route_data_from_a` (A → B direction).
    pub(super) fn claim_stream_opener(&mut self, stream_id: u32) {
        self.owned_streams_opener.insert(stream_id);
    }

    /// Returns true iff this client opened `stream_id`.
    pub(super) fn owns_stream_as_opener(&self, stream_id: u32) -> bool {
        self.owned_streams_opener.contains(&stream_id)
    }

    /// Returns true iff this client is the acceptor (B side) of `stream_id`
    /// — i.e. the per-endpoint forwarder has translated a matching
    /// `AppMessage::StreamOpen` into a `STREAM_OPEN_INBOUND` frame on this
    /// connection.
    pub(super) fn owns_stream_as_acceptor(&self, stream_id: u32) -> bool {
        self.owned_streams_acceptor
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .contains(&stream_id)
    }

    /// Drop ownership when the stream closes from this client's side, so
    /// the HashSet doesn't grow unboundedly across long-running clients.
    /// Removes from both the opener and acceptor sets — a connection can
    /// only ever be one side of any given stream_id, and the lookup is
    /// O(1) anyway.
    pub(super) fn release_stream(&mut self, stream_id: u32) {
        self.owned_streams_opener.remove(&stream_id);
        self.owned_streams_acceptor
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&stream_id);
        self.owned_streams_acceptor_routes
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&stream_id);
    }

    /// For an acceptor stream whose opener is on a REMOTE node, the wire route
    /// to forward this client's outbound STREAM_DATA / STREAM_CLOSE back to the
    /// opener. `None` for same-node (local) acceptor streams, which route via
    /// the local stream table.
    pub(super) fn acceptor_remote_route(&self, stream_id: u32) -> Option<AcceptorRemoteRoute> {
        self.owned_streams_acceptor_routes
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&stream_id)
            .copied()
    }

    /// Clone the acceptor-side remote-route handle for a forwarder task (it
    /// records the route when translating a remote-opened `AppMessage::StreamOpen`).
    pub(crate) fn acceptor_routes_handle(
        &self,
    ) -> Arc<std::sync::Mutex<std::collections::HashMap<u32, AcceptorRemoteRoute>>> {
        Arc::clone(&self.owned_streams_acceptor_routes)
    }

    /// Snapshot of every stream id this client still owns (opener ∪ acceptor).
    /// Used at disconnect to close streams the client never explicitly closed:
    /// EOF / idle / write-error exits don't send `STREAM_CLOSE`, so without this
    /// a remote-bound stream leaks — its inbound bridge stays parked on
    /// `data_rx`, its table slot is held against `MAX_TOTAL_STREAMS`, and the
    /// peer keeps its wire-side state. Deduplicated via a set: a connection is
    /// normally only one side of a given id, but a loopback open could place the
    /// id in both sets and closing twice must not double-emit a wire `AppClose`.
    pub(super) fn owned_stream_ids(&self) -> Vec<u32> {
        let mut ids: std::collections::HashSet<u32> =
            self.owned_streams_opener.iter().copied().collect();
        ids.extend(
            self.owned_streams_acceptor
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .iter()
                .copied(),
        );
        ids.into_iter().collect()
    }

    /// Clone the acceptor-side ownership handle for a forwarder task.
    /// The per-endpoint `forward_endpoint` future updates this set when
    /// it translates `AppMessage::StreamOpen`/`StreamClose` into IPC
    /// frames, so the read loop on this connection can authorise
    /// outbound STREAM_DATA frames from the acceptor SDK.
    pub(crate) fn acceptor_streams_handle(
        &self,
    ) -> Arc<std::sync::Mutex<std::collections::HashSet<u32>>> {
        Arc::clone(&self.owned_streams_acceptor)
    }

    /// True when this client has reached its per-session stream-open quota.
    pub(super) fn stream_quota_exhausted(&self) -> bool {
        self.streams_opened as usize >= veil_proto::budget::MAX_IPC_STREAMS_PER_CLIENT
    }

    /// Record a successful local stream-open.
    pub(super) fn record_stream_opened(&mut self) {
        self.streams_opened = self.streams_opened.saturating_add(1);
    }

    /// Number of currently-bound endpoints on this connection.
    pub(crate) fn endpoint_count(&self) -> usize {
        self.handles.len()
    }

    /// Clone the shared delivery-tx channel — used by stream openers to
    /// register a new outbound stream against this client's frame writer.
    pub(crate) fn delivery_tx_clone(&self) -> DeliveryQueueTx {
        self.delivery_tx.clone()
    }

    /// Cumulative count of malformed-`APP_BIND` frames seen on this connection.
    pub(crate) fn bind_decode_failures(&self) -> u32 {
        self.bind_decode_failures
    }

    /// Increment the bind-decode-failure counter (saturating).
    pub(crate) fn record_bind_decode_failure(&mut self) {
        self.bind_decode_failures = self.bind_decode_failures.saturating_add(1);
    }

    /// Register a new endpoint and spawn a forwarder task for its receiver.
    ///
    /// `socket_path` is the per-app socket file created by (if any);
    /// it will be removed when the endpoint is unbound or the client disconnects.
    pub(crate) fn add_endpoint(
        &mut self,
        handle: EndpointHandle,
        rx: mpsc::Receiver<AppMessage>,
        socket_path: Option<PathBuf>,
    ) {
        // Capture the endpoint's (app_id, endpoint_id) identity so the
        // forwarder can label inbound-stream notifications  the
        // correct routing key.  Without this the SDK would not know which
        // bound `AppHandle` to dispatch the inbound notification to.
        let endpoint_app_id = handle.key().app_id;
        let endpoint_id = handle.key().endpoint_id;
        self.handles.push((handle, socket_path));
        let tx = self.delivery_tx.clone();
        let node_id = self.node_id;
        let metrics = self.metrics.clone();
        let acceptor_streams = self.acceptor_streams_handle();
        let acceptor_routes = self.acceptor_routes_handle();
        tokio::spawn(async move {
            forward_endpoint(
                rx,
                tx,
                node_id,
                endpoint_app_id,
                endpoint_id,
                metrics,
                acceptor_streams,
                acceptor_routes,
            )
            .await;
        });
    }

    /// Returns `true` if `app_id` is registered by this client.
    fn has_app_id(&self, app_id: &[u8; 32]) -> bool {
        self.handles.iter().any(|(h, _)| h.key().app_id == *app_id)
    }

    /// Remove an endpoint by `(app_id, endpoint_id)`. The RAII handle is
    /// dropped → endpoint deregistered → forwarder task exits when its rx closes.
    /// If a per-app socket file was created, it is also removed.
    fn remove_endpoint(&mut self, app_id: &[u8; 32], endpoint_id: u32) -> bool {
        if let Some(pos) = self.handles.iter().position(|(h, _)| {
            let k = h.key();
            k.app_id == *app_id && k.endpoint_id == endpoint_id
        }) {
            let (_, socket_path) = self.handles.remove(pos);
            if let Some(path) = socket_path {
                let _ = std::fs::remove_file(&path);
            }
            true
        } else {
            false
        }
    }
}

impl Drop for IpcClientState {
    fn drop(&mut self) {
        // Remove any per-app socket files that were not explicitly unbound.
        for (_, socket_path) in &self.handles {
            if let Some(path) = socket_path {
                let _ = std::fs::remove_file(path);
            }
        }
    }
}

/// Forwarder task: receives AppMessage from the endpoint channel, encodes as
/// the appropriate IPC frame, pushes to the per-client delivery channel.
#[allow(clippy::too_many_arguments)]
async fn forward_endpoint(
    mut rx: mpsc::Receiver<AppMessage>,
    tx: impl Into<DeliveryQueueTx>,
    local_node_id: [u8; 32],
    endpoint_app_id: [u8; 32],
    endpoint_id: u32,
    metrics: Option<Arc<dyn IpcMetrics>>,
    // Audit batch 2026-05-24 (M2): `std::sync::Mutex` (NOT tokio::sync)
    // is correct here — critical sections are pure-sync `.insert()` /
    // `.remove()`, no `.await` between lock-acquire and lock-release.
    // Workspace clippy lint `await_holding_lock = "deny"` enforces this
    // invariant compile-time.  Do NOT add an `.await` inside any
    // [lock-acquire] block here.
    acceptor_streams: Arc<std::sync::Mutex<std::collections::HashSet<u32>>>,
    // Same lock discipline as `acceptor_streams` above (pure-sync insert/remove).
    acceptor_routes: Arc<std::sync::Mutex<std::collections::HashMap<u32, AcceptorRemoteRoute>>>,
) {
    let tx = tx.into();
    while let Some(msg) = rx.recv().await {
        let frame = match msg {
            AppMessage::Send(p) => {
                let deliver = AppDeliverPayload {
                    src_node_id: local_node_id,
                    src_app_id: p.src_app_id,
                    app_id: p.app_id,
                    endpoint_id: p.endpoint_id,
                    data: p.data,
                    reply_id: 0,
                };
                encode_ipc_frame(LocalAppMsg::AppDeliver as u16, &deliver.encode())
            }
            AppMessage::Deliver {
                src_node_id,
                src_app_id,
                app_id,
                endpoint_id,
                data,
                reply_id,
            } => {
                let deliver = AppDeliverPayload {
                    src_node_id,
                    src_app_id,
                    app_id,
                    endpoint_id,
                    data,
                    reply_id,
                };
                encode_ipc_frame(LocalAppMsg::AppDeliver as u16, &deliver.encode())
            }
            AppMessage::Data(p) => {
                // Bridge: AppDataPayload still carries Vec (stream path not horizontal-pool yet).
                let deliver = AppDeliverPayload {
                    src_node_id: local_node_id,
                    src_app_id: [0u8; 32], // AppDataPayload is an older path without src_app_id
                    app_id: p.app_id,
                    endpoint_id: p.endpoint_id,
                    data: veil_bufpool::pooled_shared_from_vec(p.data),
                    reply_id: 0,
                };
                encode_ipc_frame(LocalAppMsg::AppDeliver as u16, &deliver.encode())
            }
            AppMessage::StreamOpen {
                stream_id,
                src_node_id,
                initial_window,
            } => {
                // Notify the bound app that a remote peer opened a stream to
                // it.  Uses the dedicated `StreamOpenInbound` variant
                // (Phase 6.51 follow-up) — historically this was incorrectly
                // emitted as `StreamOpenOk` which collided  the
                // reply-to-outbound semantic and caused SDK clients to
                // silently drop inbound streams.
                //
                // Claim acceptor-side ownership BEFORE writing the wire
                // frame.  The SDK may pipeline a STREAM_DATA reply on the
                // very same IPC socket; if it raced ahead of this insert,
                // the read loop's authorisation check would reject the
                // first acceptor STREAM_DATA frame.  Set-then-write ensures
                // ownership is visible to the read loop in this connection
                // before the SDK can even see the stream_id.
                acceptor_streams
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .insert(stream_id);
                // When the opener is on a REMOTE node, record the wire route so
                // this client's outbound STREAM_DATA / STREAM_CLOSE can be
                // forwarded back to it (else a cross-node bidirectional stream
                // is a one-way pipe — the acceptor's replies would hit the
                // local-only `route_data_from_b` and vanish). Same-node opens
                // keep no route and route through the local stream table.
                if src_node_id != local_node_id {
                    acceptor_routes
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .insert(
                            stream_id,
                            AcceptorRemoteRoute {
                                opener_node_id: src_node_id,
                                app_id: endpoint_app_id,
                                endpoint_id,
                            },
                        );
                }
                let payload = veil_proto::StreamOpenInboundPayload {
                    stream_id,
                    app_id: endpoint_app_id,
                    endpoint_id,
                    src_node_id,
                    initial_window,
                };
                encode_ipc_frame(LocalAppMsg::StreamOpenInbound as u16, &payload.encode())
            }
            AppMessage::StreamData { stream_id, data } => {
                let payload = StreamDataPayload { stream_id, data };
                encode_ipc_frame(LocalAppMsg::StreamData as u16, &payload.encode())
            }
            AppMessage::StreamClose { stream_id } => {
                // Drop acceptor-side ownership so a later STREAM_DATA with
                // this id (e.g. a racy SDK send after the close) cannot
                // mis-route into a brand-new stream that happens to re-use
                // the same id later.
                acceptor_streams
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .remove(&stream_id);
                acceptor_routes
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .remove(&stream_id);
                let payload = StreamClosePayload { stream_id };
                encode_ipc_frame(LocalAppMsg::StreamClose as u16, &payload.encode())
            }
            AppMessage::RtData(p) => {
                // Forward as STREAM_RT_DATA with the full AppRtDataPayload body.
                encode_ipc_frame(LocalAppMsg::StreamRtData as u16, &p.encode())
            }
            // epidemic broadcasts are not forwarded via the per-endpoint
            // IPC stream (they arrive through the registry's broadcast_epidemic path
            // which fans out to all endpoints separately). Skip here.
            AppMessage::EpidemicBroadcast { .. } => continue,
            // permanent delivery failure — notify the app so it
            // can surface a send-failed event to the user. Payload = content_id.
            AppMessage::DeliveryFailed { content_id } => {
                encode_ipc_frame(LocalAppMsg::AppSendFailed as u16, &content_id)
            }
            // E2E delivery stage notification — notify the app of each
            // confirmed stage in the 5-stage receipt FSM. Payload: content_id[32] || stage[1].
            AppMessage::DeliveryStage { content_id, stage } => {
                let mut buf = [0u8; 33];
                buf[..32].copy_from_slice(&content_id);
                buf[32] = stage;
                encode_ipc_frame(LocalAppMsg::DeliveryStage as u16, &buf)
            }
        };

        // Bounded delivery: drop frame silently on backpressure, count it.
        match tx.try_send(frame) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                if let Some(ref m) = metrics {
                    m.inc_ipc_delivery_drops();
                }
            }
            Err(mpsc::error::TrySendError::Closed(_)) => break,
        }
    }
}

/// Shared pending recursive-query map.
type PendingRecursiveMap =
    Arc<Mutex<std::collections::HashMap<[u8; 16], veil_dispatcher_state::PendingRecursive>>>;

// ── IpcServer ───────────────────────────────────────────────────────────────

/// IPC server that listens on a Unix-domain socket OR a TCP-loopback port
/// for local application connections.
pub struct IpcServer {
    /// Bind target — Unix-domain socket or TCP-loopback.
    endpoint: IpcEndpoint,
    shutdown_rx: watch::Receiver<bool>,
    /// Shared endpoint registry — passed to each client handler.
    app_registry: Arc<AppEndpointRegistry>,
    /// Shared stream table — tracks active IPC streams.
    stream_table: Arc<IpcStreamTable>,
    /// Node identity — used to derive `app_id = BLAKE3(node_id || ns || name)`.
    node_id: [u8; 32],
    /// Maximum APP_SEND frames per second per client (0 = unlimited).
    max_send_rate: u32,
    /// Session outbox registry — used to route datagrams to remote peers.
    session_tx_registry: Option<Arc<dyn FrameBroadcaster>>,
    /// Cross-node IPC stream-forwarding bridge (veil_stream_rx + pending
    /// receipts + shared wire stream-id counter). `None` keeps the remote
    /// `STREAM_OPEN` path returning `REMOTE_NOT_IMPLEMENTED`.
    stream_bridge: Option<crate::bridge::IpcStreamBridge>,
    /// Route cache — used for multi-hop relay when there is no direct session.
    route_cache: Option<Arc<RwLock<veil_routing::RouteCache>>>,
    /// Notified by the dispatcher whenever a new `RouteResponse` arrives and
    /// a route is inserted into `route_cache`. Used by `handle_ipc_send` to
    /// implement reactive route discovery (wait up to 500 ms, then retry).
    route_updated: Option<Arc<tokio::sync::Notify>>,
    /// ML-KEM-768 encapsulation-key cache: `peer_id → (ek_bytes, cached_at)`.
    /// When present and the recipient's key is cached, relay-path payloads are
    /// E2E-encrypted before being wrapped in a `DeliveryEnvelope`.
    peer_mlkem_keys: Option<Arc<std::sync::RwLock<veil_e2e::PeerMlKemCache>>>,
    /// Cold-start ML-KEM-EK resolver — Epic 486.1 slice 3 (audit batch
    /// 2026-05-23).  When `Some(...)` AND the cache lookup misses in
    /// `handle_ipc_send`, the handler invokes the resolver to fetch +
    /// verify + cache the recipient's EK from the DHT.  `None`
    /// preserves the legacy "no key → NO_E2E_KEY error" semantics
    /// exactly (used by tests + setup without full NodeRuntime).
    mlkem_ek_resolver: Option<Arc<dyn veil_types::MlKemEkResolver>>,
    /// Authenticated anonymous (onion/rendezvous) sender for the
    /// `anonymous_authenticated` send flag. `None` (tests / minimal setups)
    /// makes that flag fail with `NO_RENDEZVOUS`.
    anon_onion_sender: Option<Arc<dyn veil_types::AnonOnionSender>>,
    /// Optional live-capture broadcast channel (shared with FrameDispatcher).
    /// When set, the IPC server emits plaintext capture events before E2E encryption.
    capture_tx: Option<
        Arc<Mutex<Option<tokio::sync::broadcast::Sender<veil_dispatcher_state::CaptureEvent>>>>,
    >,
    /// Fraction of outgoing APP_SEND frames that get a sampled `trace_id`.
    /// 0.0 = off, 1.0 = all.
    trace_sample_rate: f64,
    /// Pending-ACK tracker: shared with the dispatcher and the
    /// background tick task so that retransmits use the same routing path.
    pending_ack: Option<Arc<Mutex<veil_pending_ack::PendingAckTracker>>>,
    /// Pending recursive-query map: shared with the dispatcher so
    /// IPC initiators can register a oneshot, send a `RecursiveQuery`, and
    /// await the parsed `RecursiveResponse` (which has already updated
    /// `route_cache` / local DHT by the time the oneshot fires).
    pending_recursive: Option<PendingRecursiveMap>,
    /// Optional directory for per-app_id sockets.
    ///
    /// When set, a non-ephemeral APP_BIND creates `{app_socket_dir}/{hex(app_id)}.sock`
    /// with `chmod 0600`. The socket file is removed when the endpoint is unbound.
    app_socket_dir: Option<PathBuf>,
    /// Metrics handle — used to count dropped IPC delivery frames.
    metrics: Option<Arc<dyn IpcMetrics>>,
    /// Anycast service — resolves service tags to candidate node_ids.
    anycast_service: Option<Arc<veil_anycast::AnycastService>>,
    /// Transport-hint registry — answers `TransportHintQuery`
    /// with the locally-observed connect success rates per scheme.
    hint_registry: Option<Arc<veil_transport::hint_registry::TransportHintRegistry>>,
    /// Mobile event sink — receives background-mode
    /// toggles and network-state changes from connected apps.
    mobile_event_sink: Option<Arc<dyn crate::MobileEventSink>>,
    /// Daemon's signing-key wire byte and raw bytes. When
    /// set, `LocalAppMsg::GetNodeIdentity` returns these alongside the
    /// `node_id` already known to the server; otherwise the handler
    /// responds with an empty `public_key` so the client can still
    /// learn the `node_id`. Optional so unit-test fixtures don't have
    /// to fabricate a real pubkey.
    local_identity_algo: u8,
    local_identity_pubkey: Vec<u8>,
    ///.4 P0: the daemon's relay-side X25519
    /// public key that apps must seal push-envelopes against. `None`
    /// means the daemon is not relay-capable (operator did not enable
    /// `anonymity.relay_capable`). Returned to apps via
    /// `NodeIdentityPayload.relay_x25519_pubkey`.
    local_relay_x25519_pubkey: Option<[u8; 32]>,
    /// Peer-list provider — answers `LocalAppMsg::GetPeers`
    /// with a snapshot of currently-active sessions. Without it, the
    /// handler responds with an empty list so apps can detect "feature
    /// not wired" cleanly.
    peer_list_provider: Option<Arc<dyn crate::PeerListProvider>>,
    /// P-Net status provider — answers `LocalAppMsg::PnetStatusQuery`
    /// by surfacing the daemon's per-session MembershipCert verification
    /// result.  Apps (ogate / oproxy / SDK) use this to gate their
    /// admission on the daemon's already-verified cert instead of
    /// keeping a separate static `allowed_node_ids` list.  Without it,
    /// the handler replies `admitted=false / has_cert=false` so strict-
    /// p_net apps fall back to their secondary admission path.
    pnet_status_provider: Option<Arc<dyn crate::PnetStatusProvider>>,
    /// Bootstrap-URI join sink — handles
    /// `LocalAppMsg::JoinBootstrapUri` requests by decoding the URI
    /// and registering the resulting peer. Without it, the handler
    /// replies with status `INTERNAL_ERROR` + "feature not wired".
    bootstrap_join_sink: Option<Arc<dyn crate::BootstrapJoinSink>>,
    /// Mobile-status provider — answers
    /// `LocalAppMsg::GetMobileStatus` with battery + tier + factor
    /// snapshot. Without it, replies with a default zero-state payload
    /// (apps see "feature off / no battery info" cleanly).
    mobile_status_provider: Option<Arc<dyn crate::MobileStatusProvider>>,
    /// Push-event bus. When set, every connected IPC
    /// client subscribes once at handshake-finish time and receives
    /// `LocalAppMsg::Event` frames whenever the runtime publishes.
    /// Without it, no events are pushed (SDK callers see an empty
    /// receiver — feature off, no protocol error).
    event_bus: Option<Arc<crate::EventBus>>,
    /// audit M6: bounded set of permits gating concurrent IPC
    /// clients. Without it a local user spawning thousands of socket
    /// connections each pre-allocates up to 16 MiB on HELLO body read
    /// → multi-GiB transient memory. At cap, new connections drop
    /// immediately (no queue — queue would itself be unbounded).
    client_semaphore: Arc<tokio::sync::Semaphore>,
    ///.2: hook the IPC handler calls when an app sets/clears
    /// a sealed push envelope on a rendezvous-publisher entry. When `None`
    /// the handler responds with status `NoMatchingRendezvous` (feature off
    /// gracefully). Wired by the daemon so apps can register FCM/APNs
    /// tokens via a single `LocalAppMsg::SetPushEnvelope` IPC frame.
    push_envelope_sink: Option<Arc<dyn crate::PushEnvelopeSink>>,
    ///.4 P2: mailbox backend (offline store-and-forward).
    /// When `None` the IPC handlers reply with `NotMailboxRelay` (put) or
    /// empty list (fetch) / `removed = 0` (ack) — feature off gracefully.
    /// Wired by the daemon if the operator opted into mailbox role.
    mailbox_backend: Option<Arc<dyn crate::MailboxBackend>>,
    /// Offline seal/open (node-side E2E crypto for store-and-forward). When
    /// `None`, `MailboxSeal`/`MailboxOpen` reply `Failed`. Wired by the daemon.
    mailbox_crypto_sink: Option<Arc<dyn crate::MailboxCryptoSink>>,
    ///.4 P4: outbox backend (sender-side peer-sync store).
    /// When `None` the IPC handlers reply with empty list / removed=0 /
    /// stored=false — feature off gracefully.
    outbox_backend: Option<Arc<dyn crate::OutboxBackend>>,
    ///.4 P5c: rendezvous-replica resolver. When `None`
    /// the IPC handler replies with empty list (apps see "no replica
    /// found" — same as DHT miss).
    rendezvous_resolver: Option<Arc<dyn crate::RendezvousReplicaResolver>>,
    /// Epic 489.7 generator side: hook the IPC handler calls when an
    /// app sends `LocalAppMsg::CreateBootstrapInvite`.  When `None`
    /// the handler replies with status `INTERNAL_ERROR` + "feature not
    /// wired" so consumer apps can detect missing daemon support
    /// cleanly (same pattern as the other sinks).
    bootstrap_invite_create_sink: Option<Arc<dyn crate::BootstrapInviteCreateSink>>,
    /// Epic 489.8 multi-device pairing: Source side ceremony adapter.
    /// Manages a single in-flight ceremony state per daemon instance.
    pair_source_sink: Option<Arc<dyn crate::PairSourceSink>>,
    /// Epic 489.8 multi-device pairing: Target side ceremony adapter.
    pair_target_sink: Option<Arc<dyn crate::PairTargetSink>>,
}

/// Maximum concurrent IPC client connections held by the server.
/// Sized for realistic deployment: a single phone/desktop has < 10 apps using
/// veil simultaneously; 256 leaves slack for test harnesses and edge cases
/// like a browser extension with many tabs each holding a separate handle.
pub const MAX_IPC_CONCURRENT_CLIENTS: usize = 256;

/// Inter-session idle timeout for an established IPC connection (audit U3).
///
/// If NO traffic flows in EITHER direction — no client→daemon frame AND no
/// daemon→client delivery/event — for this long, the connection is closed so
/// its [`MAX_IPC_CONCURRENT_CLIENTS`] semaphore permit is released. This bounds
/// a post-HELLO slow-loris: a local process can otherwise complete the cheap
/// fixed-size HELLO on 256 connections, then go silent and pin every permit
/// forever (the only pre-existing read timeouts are the 5 s HELLO timeout and
/// the per-frame body deadline, neither of which fires between frames).
///
/// Generous on purpose: ANY real activity in either direction resets it (a
/// receiving client is kept alive by the deliveries it gets), so a legitimately
/// active connection is never dropped — only one that is fully silent both ways
/// ages out, and the SDK reconnects transparently.
pub const IPC_SESSION_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(900);

impl IpcServer {
    /// Create a new IPC server bound to the given `endpoint`.
    pub fn new(
        endpoint: IpcEndpoint,
        shutdown_rx: watch::Receiver<bool>,
        app_registry: Arc<AppEndpointRegistry>,
        node_id: [u8; 32],
    ) -> Self {
        Self {
            endpoint,
            shutdown_rx,
            app_registry,
            stream_table: Arc::new(IpcStreamTable::new()),
            node_id,
            // IPC APP_SEND rate cap. 1000 fps × MTU 65 KB = ~520 Mbps —
            // exactly the testnet ceiling we observed on ogate iperf.
            // For tunnel-style high-throughput apps (ogate) 1000 fps is
            // way too low; raised to a high ceiling that still prevents
            // runaway floods (`0` would disable entirely). Operators
            // chasing higher throughput tune this via `with_max_send_rate()`.
            max_send_rate: 1_000_000,
            session_tx_registry: None,
            stream_bridge: None,
            route_cache: None,
            route_updated: None,
            peer_mlkem_keys: None,
            mlkem_ek_resolver: None,
            anon_onion_sender: None,
            capture_tx: None,
            trace_sample_rate: 0.01,
            pending_ack: None,
            pending_recursive: None,
            app_socket_dir: None,
            metrics: None,
            anycast_service: None,
            hint_registry: None,
            mobile_event_sink: None,
            local_identity_algo: 0,
            local_identity_pubkey: Vec::new(),
            local_relay_x25519_pubkey: None,
            peer_list_provider: None,
            pnet_status_provider: None,
            bootstrap_join_sink: None,
            mobile_status_provider: None,
            event_bus: None,
            client_semaphore: Arc::new(tokio::sync::Semaphore::new(MAX_IPC_CONCURRENT_CLIENTS)),
            push_envelope_sink: None,
            mailbox_backend: None,
            mailbox_crypto_sink: None,
            outbox_backend: None,
            rendezvous_resolver: None,
            bootstrap_invite_create_sink: None,
            pair_source_sink: None,
            pair_target_sink: None,
        }
    }

    /// Attach the Source-side multi-device pairing sink (Epic 489.8).
    pub fn with_pair_source_sink(mut self, sink: Arc<dyn crate::PairSourceSink>) -> Self {
        self.pair_source_sink = Some(sink);
        self
    }

    /// Attach the Target-side multi-device pairing sink (Epic 489.8).
    pub fn with_pair_target_sink(mut self, sink: Arc<dyn crate::PairTargetSink>) -> Self {
        self.pair_target_sink = Some(sink);
        self
    }

    /// Attach a bootstrap-invite-create sink (Epic 489.7 generator
    /// side).  When set, `LocalAppMsg::CreateBootstrapInvite` is
    /// dispatched to the sink, which assembles the daemon's own
    /// invite URI.  Without it, the handler replies with status
    /// `INTERNAL_ERROR` + "feature not wired".
    pub fn with_bootstrap_invite_create_sink(
        mut self,
        sink: Arc<dyn crate::BootstrapInviteCreateSink>,
    ) -> Self {
        self.bootstrap_invite_create_sink = Some(sink);
        self
    }

    ///.2: wire the runtime's push-envelope sink so apps
    /// can register sealed FCM/APNs tokens via IPC.
    pub fn with_push_envelope_sink(mut self, sink: Arc<dyn crate::PushEnvelopeSink>) -> Self {
        self.push_envelope_sink = Some(sink);
        self
    }

    ///.4 P2: wire the mailbox backend so apps can put
    /// fetch, and ack offline-delivery blobs via IPC. Without this
    /// `MailboxPut` returns `NotMailboxRelay`, `MailboxFetch` returns
    /// an empty list, and `MailboxAck` returns `removed = 0`.
    pub fn with_mailbox_backend(mut self, backend: Arc<dyn crate::MailboxBackend>) -> Self {
        self.mailbox_backend = Some(backend);
        self
    }

    /// Wire the offline seal/open crypto sink (node-side E2E for store-and-
    /// forward delivery). Without this, `MailboxSeal`/`MailboxOpen` reply
    /// `Failed`.
    pub fn with_mailbox_crypto_sink(mut self, sink: Arc<dyn crate::MailboxCryptoSink>) -> Self {
        self.mailbox_crypto_sink = Some(sink);
        self
    }

    ///.4 P4: wire the outbox backend so apps can
    /// record / look up / ack pending peer-sync entries via IPC.
    pub fn with_outbox_backend(mut self, backend: Arc<dyn crate::OutboxBackend>) -> Self {
        self.outbox_backend = Some(backend);
        self
    }

    ///.4 P5c: wire the rendezvous-replica resolver so
    /// apps can find K candidate mailbox-relays for a receiver via
    /// IPC `LookupRendezvousReplicas`. Without it, the handler
    /// always returns an empty list.
    pub fn with_rendezvous_resolver(
        mut self,
        resolver: Arc<dyn crate::RendezvousReplicaResolver>,
    ) -> Self {
        self.rendezvous_resolver = Some(resolver);
        self
    }

    /// Enable per-app_id socket mode.
    ///
    /// After this call, non-ephemeral `APP_BIND` requests will create a
    /// dedicated Unix socket at `{dir}/{hex(app_id)}.sock` with `0600` permissions.
    pub fn with_app_socket_dir(mut self, dir: PathBuf) -> Self {
        self.app_socket_dir = Some(dir);
        self
    }

    /// Override the per-client APP_SEND rate limit (messages/second).
    pub fn with_max_send_rate(mut self, rate: u32) -> Self {
        self.max_send_rate = rate;
        self
    }

    /// Attach the session outbox registry so that remote IPC sends are forwarded
    /// over the active OVL1 session to the destination peer.
    pub fn with_session_tx_registry(mut self, reg: Arc<dyn FrameBroadcaster>) -> Self {
        self.session_tx_registry = Some(reg);
        self
    }

    /// Attach the cross-node stream-forwarding bridge so `STREAM_OPEN` to a
    /// remote `dst_node_id` bridges onto the wire `AppOpen`/`AppData`/`AppClose`
    /// machinery instead of returning `REMOTE_NOT_IMPLEMENTED`.
    pub fn with_stream_bridge(mut self, bridge: crate::bridge::IpcStreamBridge) -> Self {
        self.stream_bridge = Some(bridge);
        self
    }

    /// Attach the route cache so that APP_SEND frames can be relayed via a
    /// next-hop when no direct session exists.
    pub fn with_route_cache(mut self, cache: Arc<RwLock<veil_routing::RouteCache>>) -> Self {
        self.route_cache = Some(cache);
        self
    }

    /// Attach the route-updated notifier so that `handle_ipc_send` can wait
    /// for reactive route discovery.
    pub fn with_route_updated(mut self, notify: Arc<tokio::sync::Notify>) -> Self {
        self.route_updated = Some(notify);
        self
    }

    /// Attach the peer ML-KEM key cache for E2E encryption on relay-path sends
    ///. Only the *recipient's* encapsulation key is needed here;
    /// the local decapsulation key is only used in `FrameDispatcher` for
    /// decrypting *incoming* envelopes.
    pub fn with_e2e_keys(
        mut self,
        peer_mlkem_keys: Arc<std::sync::RwLock<veil_e2e::PeerMlKemCache>>,
    ) -> Self {
        self.peer_mlkem_keys = Some(peer_mlkem_keys);
        self
    }

    /// Attach the cold-start ML-KEM-EK resolver.  When the `with_e2e_keys`
    /// cache misses for a target node_id, the IPC send-handler invokes
    /// this resolver to fetch the recipient's EK from the DHT (instance
    /// registry walk + cert chain verification) and cache it on success.
    /// Without the resolver, cache misses surface as `NO_E2E_KEY` errors
    /// (legacy behaviour preserved).  Epic 486.1 slice 3, audit batch
    /// 2026-05-23.
    pub fn with_mlkem_ek_resolver(
        mut self,
        resolver: Arc<dyn veil_types::MlKemEkResolver>,
    ) -> Self {
        self.mlkem_ek_resolver = Some(resolver);
        self
    }

    /// Attach the authenticated anonymous (onion/rendezvous) sender used by the
    /// `anonymous_authenticated` send flag.
    pub fn with_anon_onion_sender(mut self, sender: Arc<dyn veil_types::AnonOnionSender>) -> Self {
        self.anon_onion_sender = Some(sender);
        self
    }

    /// Attach the live-capture broadcast channel so the IPC server can emit
    /// plaintext capture events for outbound E2E-encrypted frames.
    pub fn with_capture_tx(
        mut self,
        capture_tx: Arc<
            Mutex<Option<tokio::sync::broadcast::Sender<veil_dispatcher_state::CaptureEvent>>>,
        >,
    ) -> Self {
        self.capture_tx = Some(capture_tx);
        self
    }

    /// Set the trace sampling rate. Default: 0.01 (1 %).
    pub fn with_trace_sample_rate(mut self, rate: f64) -> Self {
        self.trace_sample_rate = rate.clamp(0.0, 1.0);
        self
    }

    /// Attach the metrics handle for delivery-drop counting.
    pub fn with_metrics(mut self, metrics: Arc<dyn IpcMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Attach the pending-ACK tracker.
    pub fn with_pending_ack(
        mut self,
        tracker: Arc<Mutex<veil_pending_ack::PendingAckTracker>>,
    ) -> Self {
        self.pending_ack = Some(tracker);
        self
    }

    /// Attach the pending recursive-query map shared with the
    /// dispatcher, enabling IPC reactive discovery to await parsed responses.
    pub fn with_pending_recursive(mut self, map: PendingRecursiveMap) -> Self {
        self.pending_recursive = Some(map);
        self
    }

    /// Attach the anycast service for service-tag resolution.
    pub fn with_anycast_service(mut self, svc: Arc<veil_anycast::AnycastService>) -> Self {
        self.anycast_service = Some(svc);
        self
    }

    /// Attach the transport-hint registry so `TransportHintQuery`
    /// returns ranked schemes from the registry's live observations.
    pub fn with_hint_registry(
        mut self,
        registry: Arc<veil_transport::hint_registry::TransportHintRegistry>,
    ) -> Self {
        self.hint_registry = Some(registry);
        self
    }

    /// Attach the mobile event sink. When set, the
    /// IPC dispatcher routes `SetMobileBackgroundMode` and `NetworkChanged`
    /// payloads to the sink; without it, those messages are silently
    /// ignored (caller-friendly default for non-mobile deployments).
    pub fn with_mobile_event_sink(mut self, sink: Arc<dyn crate::MobileEventSink>) -> Self {
        self.mobile_event_sink = Some(sink);
        self
    }

    /// Attach the daemon's signing-key wire byte + raw public-key bytes
    /// so `LocalAppMsg::GetNodeIdentity` can return them.
    /// When unset, the handler returns an empty `public_key` (still
    /// valid wire format — clients learn `node_id` only).
    pub fn with_local_identity(mut self, algo: u8, public_key: Vec<u8>) -> Self {
        self.local_identity_algo = algo;
        self.local_identity_pubkey = public_key;
        self
    }

    ///.4 P0: wire the relay-side X25519
    /// public key that apps must seal push-envelopes against. Returned
    /// alongside the signing pubkey via `NodeIdentityPayload`. `None`
    /// (the default) means the daemon is not relay-capable, and apps
    /// must pick a different relay for push-envelope sealing.
    pub fn with_relay_x25519_pubkey(mut self, pubkey: [u8; 32]) -> Self {
        self.local_relay_x25519_pubkey = Some(pubkey);
        self
    }

    /// Attach a peer-list provider. When set
    /// `LocalAppMsg::GetPeers` snapshots active sessions via the
    /// provider and replies with `PeersList`. Without it, the reply is
    /// always empty.
    pub fn with_peer_list_provider(mut self, provider: Arc<dyn crate::PeerListProvider>) -> Self {
        self.peer_list_provider = Some(provider);
        self
    }

    /// Attach a P-Net status provider. When set
    /// `LocalAppMsg::PnetStatusQuery` is routed to the provider and the
    /// reply carries verified MembershipCert state.  Without it, the
    /// reply is always `admitted=false / has_cert=false` so apps in
    /// strict p_net mode reject and fall back to their secondary path.
    pub fn with_pnet_status_provider(
        mut self,
        provider: Arc<dyn crate::PnetStatusProvider>,
    ) -> Self {
        self.pnet_status_provider = Some(provider);
        self
    }

    /// Attach a bootstrap-join sink. When set
    /// `LocalAppMsg::JoinBootstrapUri` is dispatched to the sink for
    /// URI decode + verify + peer registration. Without it, the
    /// handler replies with status `INTERNAL_ERROR` so apps can detect
    /// "feature not wired" cleanly.
    pub fn with_bootstrap_join_sink(mut self, sink: Arc<dyn crate::BootstrapJoinSink>) -> Self {
        self.bootstrap_join_sink = Some(sink);
        self
    }

    /// Attach a mobile-status provider. When set
    /// `LocalAppMsg::GetMobileStatus` snapshots the daemon's current
    /// mobile/battery state via the provider. Without it, replies
    /// with a default zero-state payload — apps see the feature as off
    /// rather than a protocol error.
    pub fn with_mobile_status_provider(
        mut self,
        provider: Arc<dyn crate::MobileStatusProvider>,
    ) -> Self {
        self.mobile_status_provider = Some(provider);
        self
    }

    /// Attach a push-event bus. Every IPC client subscribes
    /// once at connect time and receives a copy of every `EventPayload`
    /// the runtime publishes as a `LocalAppMsg::Event` frame. Without
    /// it, no push events are emitted — SDK consumers see an empty
    /// receiver, which lets the runtime stay event-source-agnostic
    /// (the bus binds publishers to subscribers).
    pub fn with_event_bus(mut self, bus: Arc<crate::EventBus>) -> Self {
        self.event_bus = Some(bus);
        self
    }

    /// Run the accept loop. Dispatches on the configured backend:
    /// `IpcEndpoint::Unix(path)` — atomic socket recreation via `bind ⇒
    /// chmod ⇒ rename` (race fix preserved).
    /// `IpcEndpoint::Tcp { bind_addr, runtime_dir }` — bind TCP listener
    /// write `ipc.port` + `ipc.token` sidecars to `runtime_dir` so clients
    /// can authenticate.
    pub async fn run(&mut self) -> std::io::Result<()> {
        match self.endpoint.clone() {
            IpcEndpoint::Unix(path) => self.run_unix(path).await,
            IpcEndpoint::Tcp {
                bind_addr,
                runtime_dir,
            } => self.run_tcp(bind_addr, runtime_dir).await,
            #[cfg(windows)]
            IpcEndpoint::NamedPipe {
                pipe_name,
                runtime_dir,
            } => self.run_named_pipe(pipe_name, runtime_dir).await,
            #[cfg(not(windows))]
            IpcEndpoint::NamedPipe { .. } => Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "NamedPipe IPC endpoint is only supported on Windows",
            )),
        }
    }

    async fn run_unix(&mut self, socket_path: PathBuf) -> std::io::Result<()> {
        // atomic socket recreation. See git history for full
        // rationale; in short we bind to a `.tmp` path, chmod 0600 *then*
        // rename — eliminating the TOCTOU window between remove+bind that a
        // naive flow exposes.
        if let Some(parent) = socket_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp_path = socket_path.with_extension("tmp");
        let _ = std::fs::remove_file(&tmp_path);
        let listener = transport::bind_unix(&tmp_path)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&tmp_path, perms)?;
        }
        std::fs::rename(&tmp_path, &socket_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&socket_path, perms)?;
        }

        self.accept_loop(&listener).await;

        let _ = std::fs::remove_file(&socket_path);
        Ok(())
    }

    async fn run_tcp(
        &mut self,
        bind_addr: std::net::SocketAddr,
        runtime_dir: PathBuf,
    ) -> std::io::Result<()> {
        std::fs::create_dir_all(&runtime_dir)?;
        let (listener, local_addr, token) = transport::bind_tcp(bind_addr).await?;
        // write port + token through atomic
        // `OpenOptions::mode(0o600).create(true)` helpers (in
        // `veil-local-transport`) instead of a `std::fs::write` +
        // post-chmod sequence. The old sequence had a TOCTOU window
        // between create-with-default-umask (often 0o644) and the
        // chmod to 0o600 — any local process on the same uid range
        // could scrape the token off disk during that millisecond.
        // The helper also zeroizes the hex copy of the token on drop.
        transport::write_port_file(&runtime_dir.join(IPC_PORT_FILENAME), local_addr.port()).await?;
        transport::write_token_file(&runtime_dir.join(IPC_TOKEN_FILENAME), &token).await?;

        self.accept_loop(&listener).await;

        let _ = std::fs::remove_file(runtime_dir.join(IPC_PORT_FILENAME));
        let _ = std::fs::remove_file(runtime_dir.join(IPC_TOKEN_FILENAME));
        Ok(())
    }

    /// Windows NamedPipe backend. Mirrors `run_tcp` but binds
    /// the underlying `LocalListener::NamedPipe` and writes `ipc.pipe` (the
    /// pipe name) instead of `ipc.port` (a number) as the discovery sidecar.
    /// The per-accept work in `accept_loop` is identical — every backend
    /// produces the same `LocalStream` shape.
    #[cfg(windows)]
    async fn run_named_pipe(
        &mut self,
        pipe_name: String,
        runtime_dir: PathBuf,
    ) -> std::io::Result<()> {
        std::fs::create_dir_all(&runtime_dir)?;
        let (listener, actual_name, token) = veil_local_transport::bind_named_pipe(&pipe_name)?;
        // route the token write through
        // `write_token_file` for hex-buffer zeroize parity with the
        // TCP backend. On Windows the `mode(0o600)` is a no-op (NTFS
        // ACLs would need a separate mechanism —), but
        // the runtime-dir ACL inherited on `create_dir_all` already
        // restricts to the local user. The pipe-name sidecar is non-
        // secret discovery data; plain write is fine.
        std::fs::write(runtime_dir.join(IPC_PIPE_FILENAME), actual_name.as_bytes())?;
        transport::write_token_file(&runtime_dir.join(IPC_TOKEN_FILENAME), &token).await?;

        self.accept_loop(&listener).await;

        let _ = std::fs::remove_file(runtime_dir.join(IPC_PIPE_FILENAME));
        let _ = std::fs::remove_file(runtime_dir.join(IPC_TOKEN_FILENAME));
        Ok(())
    }

    /// Shared accept loop — used by both Unix and TCP backends. Each
    /// `IpcStream` is dispatched to a per-connection task; the per-connection
    /// state is cloned out of `&self` once per accept so the spawned task is
    /// fully `'static`.
    async fn accept_loop(&mut self, listener: &transport::IpcListener) {
        let mut shutdown_rx = self.shutdown_rx.clone();

        // A2 glue: periodic stream-idle reaper. The
        // primitive shipped in `IpcStreamTable` (commit `6a1588b`) exposed
        // `reap_stale(idle_timeout) -> Vec<u32>`; this is the caller-side
        // wiring that makes it actually fire. Without a periodic invocation
        // a stream that broke without a CLOSE frame would sit in the table
        // forever, holding the per-stream watermarks and (more importantly)
        // the slot's window-update buffer. Slow-reader DoS protected.
        //
        // 60 s tick is a compromise: shorter would burn CPU on no-op
        // sweeps; longer leaves orphaned streams alive past the
        // `DEFAULT_STREAM_IDLE_TIMEOUT = 5 min` window long enough to
        // matter under sustained orphan-rate. Reaper exits when the
        // shutdown signal fires.
        let reaper_streams = Arc::clone(&self.stream_table);
        let reaper_broadcaster = self.session_tx_registry.clone();
        let reaper_bridge = self.stream_bridge.clone();
        let mut reaper_shutdown = self.shutdown_rx.clone();
        let reaper_handle = tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    biased;
                    changed = reaper_shutdown.changed() => {
                        if changed.is_ok() && *reaper_shutdown.borrow() { break; }
                    }
                    _ = tick.tick() => {
                        let _evicted = reaper_streams
                            .reap_stale(crate::streams::DEFAULT_STREAM_IDLE_TIMEOUT);
                        // Eviction count not surfaced here intentionally
                        // — operators noticing high stream churn should
                        // look at IPC metrics, not parse log lines.

                        // Companion sweep for remote-bound streams (the sibling
                        // map `reap_stale` does not touch). For each evicted
                        // remote stream, tell the peer to release its wire-side
                        // state and drop the inbound bridge registration so the
                        // parked per-stream bridge task observes its `data_rx`
                        // close and exits.
                        for target in reaper_streams
                            .reap_stale_remote(crate::streams::DEFAULT_STREAM_IDLE_TIMEOUT)
                        {
                            teardown_remote_target(
                                &target,
                                reaper_broadcaster.as_deref(),
                                reaper_bridge.as_ref(),
                            );
                        }
                    }
                }
            }
        });

        let result = self.accept_loop_inner(listener, &mut shutdown_rx).await;

        // Reaper task exits on its own when shutdown_rx fires; reach in
        // and await its completion so it doesn't leak past `run`'s scope.
        let _ = reaper_handle.await;

        result
    }

    /// Inner accept loop split out from [`Self::accept_loop`] so the
    /// outer wrapper can spawn a parallel reaper task without duplicating
    /// the shutdown / accept select logic.
    async fn accept_loop_inner(
        &mut self,
        listener: &transport::IpcListener,
        shutdown_rx: &mut watch::Receiver<bool>,
    ) {
        loop {
            tokio::select! {
                // biased: on shutdown, don't accept a new client that races
                // the signal — pick the shutdown branch first.
                biased;
                changed = shutdown_rx.changed() => {
                    if changed.is_ok() && *shutdown_rx.borrow() { break; }
                }
                accepted = listener.accept_raw() => {
                    // slow-loris fix: `accept_raw` returns
                    // immediately after kernel TCP-accept, without awaiting
                    // the 32-byte token handshake. The handshake (which
                    // can stall up to TOKEN_READ_TIMEOUT=3s on a malicious
                    // client) runs inside the spawned task below, so the
                    // accept loop is never blocked by stragglers.
                    if let Ok((pending, peer_info)) = accepted {
                        // audit U9: enforce the per-connection peer-uid match as
                        // a kernel-level secondary gate, mirroring the admin
                        // plane (admin.rs). On Unix this rejects a cross-user
                        // connection (SO_PEERCRED / getpeereid) even if the
                        // socket's 0o600 mode were ever loosened or the socket
                        // sat in a sticky world-writable dir; on TCP / named-pipe
                        // backends `uid_matches_local` is always true, so this is
                        // a no-op there. The IPC plane carries powerful ops
                        // (send-as-node, GetPeers, bootstrap joins), so it should
                        // not rely on the on-disk socket mode alone.
                        if !peer_info.uid_matches_local {
                            drop(pending);
                            continue;
                        }
                        // audit M6: cap concurrent IPC clients.
                        // Without semaphore a local user can spawn thousands of
                        // unix-socket connections, each pre-allocating up to
                        // 16 MiB on HELLO body read → multi-GiB transient OOM.
                        // try_acquire_owned drops the new connection if cap
                        // reached (queue would itself be unbounded).
                        let permit = match self.client_semaphore.clone().try_acquire_owned() {
                            Ok(p) => p,
                            Err(_) => {
                                drop(pending);
                                continue;
                            }
                        };
                        let registry = Arc::clone(&self.app_registry);
                        let streams = Arc::clone(&self.stream_table);
                        let node_id = self.node_id;
                        let max_rate = self.max_send_rate;
                        let tx_reg = self.session_tx_registry.clone();
                        let stream_bridge = self.stream_bridge.clone();
                        let route_cache = self.route_cache.clone();
                        let route_updated = self.route_updated.clone();
                        let peer_mlkem_keys = self.peer_mlkem_keys.clone();
                        let mlkem_ek_resolver = self.mlkem_ek_resolver.clone();
                        let anon_onion_sender = self.anon_onion_sender.clone();
                        let capture_tx = self.capture_tx.clone();
                        let trace_sample_rate = self.trace_sample_rate;
                        let pending_ack = self.pending_ack.clone();
                        let pending_recursive = self.pending_recursive.clone();
                        let app_socket_dir = self.app_socket_dir.clone();
                        let metrics = self.metrics.clone();
                        let anycast_service = self.anycast_service.clone();
                        let hint_registry = self.hint_registry.clone();
                        let mobile_event_sink = self.mobile_event_sink.clone();
                        let local_identity_algo = self.local_identity_algo;
                        let local_identity_pubkey = self.local_identity_pubkey.clone();
                        let local_relay_x25519_pubkey = self.local_relay_x25519_pubkey;
                        let peer_list_provider = self.peer_list_provider.clone();
                        let pnet_status_provider = self.pnet_status_provider.clone();
                        let bootstrap_join_sink = self.bootstrap_join_sink.clone();
                        let mobile_status_provider = self.mobile_status_provider.clone();
                        let event_bus = self.event_bus.clone();
                        let push_envelope_sink = self.push_envelope_sink.clone();
                        let mailbox_backend = self.mailbox_backend.clone();
                        let mailbox_crypto_sink = self.mailbox_crypto_sink.clone();
                        let outbox_backend = self.outbox_backend.clone();
                        let rendezvous_resolver = self.rendezvous_resolver.clone();
                        let bootstrap_invite_create_sink =
                            self.bootstrap_invite_create_sink.clone();
                        let pair_source_sink = self.pair_source_sink.clone();
                        let pair_target_sink = self.pair_target_sink.clone();
                        tokio::spawn(async move {
                            // Hold the M6 semaphore permit for the lifetime of
                            // the client task — drops automatically when task
                            // exits, releasing the slot for the next accept.
                            let _permit = permit;
                            // complete the token-handshake step
                            // here (off the accept loop). Failures (timeout
                            // mismatch, EOF) drop the connection silently —
                            // typical for a probe or misconfigured client.
                            let stream = match pending.verify().await {
                                Ok(s) => s,
                                Err(_) => return,
                            };
                            // Surface errors that ended the client task so
                            // operators can diagnose IPC disconnects without
                            // strace. Tracing is wired in at log-level WARN
                            // by the daemon binary.
                            if let Err(e) = handle_ipc_client(stream, registry, streams, node_id, max_rate, tx_reg, route_cache, route_updated, peer_mlkem_keys, mlkem_ek_resolver, anon_onion_sender, capture_tx, trace_sample_rate, pending_ack, pending_recursive, app_socket_dir, metrics, anycast_service, hint_registry, mobile_event_sink, local_identity_algo, local_identity_pubkey, local_relay_x25519_pubkey, peer_list_provider, bootstrap_join_sink, mobile_status_provider, event_bus, push_envelope_sink, mailbox_backend, mailbox_crypto_sink, outbox_backend, rendezvous_resolver, bootstrap_invite_create_sink, pair_source_sink, pair_target_sink, pnet_status_provider, stream_bridge).await {
                                eprintln!("[veil-ipc] client disconnected: {e} (kind={:?})", e.kind());
                            }
                        });
                    }
                }
            }
        }
    }
}

// ── Per-client handler ──────────────────────────────────────────────────────

/// Aborts the wrapped task when dropped.
///
/// Used for the per-connection read-half task so it is torn down on EVERY exit
/// path of `handle_ipc_client` — including `?` error propagation out of a frame
/// handler (e.g. a handler hitting its decode-failure cap) — not only the
/// `select!`-loop `break`. The previous explicit `read_task.abort()` after the
/// loop was bypassed on those error-exit paths, leaking the read task parked in
/// `read_frame` and holding the socket read-half fd open (audit M4, completing
/// U3).
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Emit the wire `AppClose` to the peer and drop the inbound bridge
/// registration for a remote-bound stream whose table entry has **already**
/// been removed (by `close_remote` / `reap_stale_remote`). Freeing the peer's
/// wire-side state + removing `veil_stream_rx` lets the parked per-stream
/// bridge task observe its `data_rx` close and wind down.
fn teardown_remote_target(
    target: &crate::streams::RemoteStreamTarget,
    session_tx_registry: Option<&dyn FrameBroadcaster>,
    stream_bridge: Option<&crate::bridge::IpcStreamBridge>,
) {
    if let Some(b) = session_tx_registry {
        crate::handlers::stream::send_app_close(
            b,
            &target.dst_node_id,
            target.wire_stream_id,
            target.app_id,
            target.endpoint_id,
        );
    }
    if let Some(bridge) = stream_bridge {
        bridge
            .veil_stream_rx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&(target.dst_node_id, target.wire_stream_id));
    }
}

/// Tear down one IPC stream the client owns, mirroring the `STREAM_CLOSE`
/// read-loop arm so explicit-close and implicit (disconnect) teardown stay
/// identical. Remote-bound → wire `AppClose` + bridge teardown; local pair →
/// notify both endpoints. Idempotent: a second call for an already-closed id is
/// a no-op (`close_remote` returns `None`, `close` early-returns).
fn close_owned_stream(
    stream_id: u32,
    stream_table: &IpcStreamTable,
    session_tx_registry: Option<&dyn FrameBroadcaster>,
    stream_bridge: Option<&crate::bridge::IpcStreamBridge>,
) {
    if let Some(target) = stream_table.close_remote(stream_id) {
        teardown_remote_target(&target, session_tx_registry, stream_bridge);
    } else {
        stream_table.close(stream_id);
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_ipc_client(
    mut stream: IpcStream,
    app_registry: Arc<AppEndpointRegistry>,
    stream_table: Arc<IpcStreamTable>,
    node_id: [u8; 32],
    max_send_rate: u32,
    session_tx_registry: Option<Arc<dyn FrameBroadcaster>>,
    route_cache: Option<Arc<RwLock<veil_routing::RouteCache>>>,
    route_updated: Option<Arc<tokio::sync::Notify>>,
    peer_mlkem_keys: Option<Arc<std::sync::RwLock<veil_e2e::PeerMlKemCache>>>,
    mlkem_ek_resolver: Option<Arc<dyn veil_types::MlKemEkResolver>>,
    anon_onion_sender: Option<Arc<dyn veil_types::AnonOnionSender>>,
    capture_tx: Option<
        Arc<Mutex<Option<tokio::sync::broadcast::Sender<veil_dispatcher_state::CaptureEvent>>>>,
    >,
    trace_sample_rate: f64,
    pending_ack: Option<Arc<Mutex<veil_pending_ack::PendingAckTracker>>>,
    pending_recursive: Option<PendingRecursiveMap>,
    app_socket_dir: Option<PathBuf>,
    metrics: Option<Arc<dyn IpcMetrics>>,
    anycast_service: Option<Arc<veil_anycast::AnycastService>>,
    hint_registry: Option<Arc<veil_transport::hint_registry::TransportHintRegistry>>,
    mobile_event_sink: Option<Arc<dyn crate::MobileEventSink>>,
    local_identity_algo: u8,
    local_identity_pubkey: Vec<u8>,
    local_relay_x25519_pubkey: Option<[u8; 32]>,
    peer_list_provider: Option<Arc<dyn crate::PeerListProvider>>,
    bootstrap_join_sink: Option<Arc<dyn crate::BootstrapJoinSink>>,
    mobile_status_provider: Option<Arc<dyn crate::MobileStatusProvider>>,
    event_bus: Option<Arc<crate::EventBus>>,
    push_envelope_sink: Option<Arc<dyn crate::PushEnvelopeSink>>,
    mailbox_backend: Option<Arc<dyn crate::MailboxBackend>>,
    mailbox_crypto_sink: Option<Arc<dyn crate::MailboxCryptoSink>>,
    outbox_backend: Option<Arc<dyn crate::OutboxBackend>>,
    rendezvous_resolver: Option<Arc<dyn crate::RendezvousReplicaResolver>>,
    bootstrap_invite_create_sink: Option<Arc<dyn crate::BootstrapInviteCreateSink>>,
    pair_source_sink: Option<Arc<dyn crate::PairSourceSink>>,
    pair_target_sink: Option<Arc<dyn crate::PairTargetSink>>,
    pnet_status_provider: Option<Arc<dyn crate::PnetStatusProvider>>,
    stream_bridge: Option<crate::bridge::IpcStreamBridge>,
) -> std::io::Result<()> {
    // ── Step 1: read APP_HELLO ──────────────────────────────────────────
    // Bound the entire pre-handshake read by a 5-second timeout AND
    // assert exact `body_len == AppIpcHelloPayload::WIRE_SIZE` so a
    // local attacker (compromised user-side process, sandbox escape)
    // cannot force a 16 MiB pre-allocation per connection × N
    // connections to exhaust daemon RAM before version negotiation.
    // HELLO payload is fixed 6 bytes; anything else is a bug or attack.
    const HELLO_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
    let hello = tokio::time::timeout(HELLO_READ_TIMEOUT, async {
        let mut hdr_buf = [0u8; veil_proto::HEADER_SIZE];
        stream.read_exact(&mut hdr_buf).await?;
        let header = codec::decode_header(&hdr_buf)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        if header.family != FrameFamily::LocalApp as u8
            || header.msg_type != LocalAppMsg::AppHello as u16
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "expected APP_HELLO",
            ));
        }
        // exact-size guard. decode_header bounds
        // body_len by MAX_FRAME_BODY (16 MiB); we tighten to the actual
        // payload size before allocating.
        if header.body_len as usize != AppIpcHelloPayload::WIRE_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "APP_HELLO body_len must be {} (got {})",
                    AppIpcHelloPayload::WIRE_SIZE,
                    header.body_len,
                ),
            ));
        }
        let mut body = [0u8; AppIpcHelloPayload::WIRE_SIZE];
        stream.read_exact(&mut body).await?;
        AppIpcHelloPayload::decode(&body)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
    })
    .await
    .map_err(|_elapsed| {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "APP_HELLO read timed out (5s) — client did not handshake",
        )
    })??;

    // ── Step 2: version check ───────────────────────────────────────────
    if hello.version < CLIENT_MIN_VERSION || hello.version > CLIENT_MAX_VERSION {
        let err = AppIpcHelloErrPayload {
            error_code: ipc_hello_err::VERSION_MISMATCH,
            detail: format!(
                "server accepts versions {}-{}, client requested {}",
                CLIENT_MIN_VERSION, CLIENT_MAX_VERSION, hello.version
            )
            .into_bytes(),
        };
        write_frame_stream(
            &mut stream,
            FrameFamily::LocalApp as u8,
            LocalAppMsg::AppHelloErr as u16,
            &err.encode(),
        )
        .await?;
        return Ok(());
    }

    // ── Step 3: reply APP_HELLO_OK ──────────────────────────────────────
    let client_token = generate_client_token();
    let ok = AppIpcHelloOkPayload {
        version: IPC_PROTOCOL_VERSION,
        client_token,
    };
    write_frame_stream(
        &mut stream,
        FrameFamily::LocalApp as u8,
        LocalAppMsg::AppHelloOk as u16,
        &ok.encode(),
    )
    .await?;

    // ── Step 4: split socket + bidirectional message loop ───────────────
    let (mut rh, mut wh) = stream.into_split();
    let (delivery_tx, mut delivery_rx, delivery_inflight) = delivery_queue(
        veil_proto::budget::DELIVERY_CHANNEL_CAP,
        veil_proto::budget::MAX_DELIVERY_INFLIGHT_BYTES,
    );
    let mut client_state = IpcClientState::new(delivery_tx, node_id, client_token, metrics);
    let mut rate_limiter: Option<TokenBucket> = if max_send_rate > 0 {
        Some(TokenBucket::new(max_send_rate as f64, max_send_rate as f64))
    } else {
        None
    };

    // The read side must stay cancellation-safe across `select!` cycles.
    // `read_frame` calls `read_exact` twice (header + body), neither of
    // which is cancel-safe — when `select!` cancels a partially-read
    // frame because the other arm fires, bytes have already been
    // consumed from the socket but the framing state is lost. Next
    // poll tries to decode a fresh header from continuation bytes
    // garbage results, the loop eventually exits silently with
    // Ok, and the IPC client churns at high traffic.
    //
    // Fix: read frames in a dedicated task and forward them through an
    // mpsc channel. Channel recv IS cancel-safe, so the main loop's
    // select! never throws away in-flight bytes.
    let (frame_tx, mut frame_rx) = mpsc::channel::<(FrameHeader, veil_bufpool::Pooled)>(64);
    // Wrapped in `AbortOnDrop` so the read-half task is aborted on every exit
    // path of this function (loop break AND `?` error propagation), not just
    // the post-loop teardown — see `AbortOnDrop` (audit M4, completing U3).
    let _read_task = AbortOnDrop(tokio::spawn(async move {
        loop {
            match read_frame(&mut rh).await {
                Ok(f) => {
                    if frame_tx.send(f).await.is_err() {
                        return; // main loop is gone — quit.
                    }
                }
                Err(_) => return, // peer hung up or framing error.
            }
        }
    }));

    // Push-event subscription. Subscribe once per IPC
    // client; broadcast::Receiver::recv is cancel-safe so it composes
    // cleanly with the existing select!. When the bus is unset we
    // park on a never-ready future so the arm contributes nothing to
    // wakeups — same pattern veil-types uses for optional inputs.
    let mut event_rx: Option<tokio::sync::broadcast::Receiver<veil_proto::EventPayload>> =
        event_bus.as_ref().map(|bus| bus.subscribe());

    // Bidirectional idle timeout (audit U3): reset on any activity in either
    // direction; fires only when the connection is fully silent both ways for
    // IPC_SESSION_IDLE_TIMEOUT, at which point we close it to release the M6
    // semaphore permit (post-HELLO slow-loris defence).
    let idle = tokio::time::sleep(IPC_SESSION_IDLE_TIMEOUT);
    tokio::pin!(idle);
    let bump = || tokio::time::Instant::now() + IPC_SESSION_IDLE_TIMEOUT;

    loop {
        tokio::select! {
            // Incoming veil → IPC delivery
            Some(frame_bytes) = delivery_rx.recv() => {
                // Release the in-flight byte budget reserved at enqueue as soon
                // as the frame leaves the queue for the socket.
                delivery_inflight.fetch_sub(frame_bytes.len(), Ordering::AcqRel);
                idle.as_mut().reset(bump());
                if wh.write_all(&frame_bytes).await.is_err() {
                    break;
                }
            }

            // Push event → IPC client.
            //
            // The arm's branch future blocks on the broadcast receiver if a
            // bus is wired, otherwise on `pending` which never resolves.
            // RecvError::Lagged signals that this slow consumer fell behind
            // the bus capacity — surface it on stderr but keep the
            // connection alive (the SDK just missed an intermediate state
            // not a fatal protocol error). RecvError::Closed only fires
            // when every Sender has dropped; treat that as "bus gone for
            // good" and stop polling that arm.
            event_recv = async {
                match event_rx.as_mut() {
                    Some(rx) => rx.recv().await.map(Some),
                    None => std::future::pending::<Result<Option<veil_proto::EventPayload>, tokio::sync::broadcast::error::RecvError>>().await,
                }
            } => {
                idle.as_mut().reset(bump());
                match event_recv {
                    Ok(Some(event)) => {
                        let body = event.encode();
                        if write_frame_wh(
                            &mut wh,
                            FrameFamily::LocalApp as u8,
                            LocalAppMsg::Event as u16,
                            &body,
                        ).await.is_err() {
                            break;
                        }
                    }
                    Ok(None) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        eprintln!(
                            "[veil-ipc] event subscriber lagged, dropped {n} events"
                        );
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        // Bus shut down; drop our handle so the arm becomes
                        // pending forever and we don't spin on closed-rx.
                        event_rx = None;
                    }
                }
            }

            // Incoming frame from IPC client (now arrives via channel — cancel-safe)
            maybe_frame = frame_rx.recv() => {
                idle.as_mut().reset(bump());
                let (hdr, body) = match maybe_frame {
                    Some(f) => f,
                    None => break,
                };

                if hdr.family != FrameFamily::LocalApp as u8 {
                    continue;
                }

                match LocalAppMsg::try_from(hdr.msg_type) {
                    Ok(LocalAppMsg::AppBind) => {
                        {
                            let token = client_state.client_token;
                            handle_bind(&mut wh, &body, &mut client_state, &app_registry, &node_id, &token, app_socket_dir.as_deref()).await?;
                        }
                    }
                    Ok(LocalAppMsg::AppUnbind) => {
                        if let Ok(u) = AppUnbindPayload::decode(&body) {
                            client_state.remove_endpoint(&u.app_id, u.endpoint_id);
                        }
                    }
                    Ok(LocalAppMsg::AppIpcSend) => {
                        // validate src_app_id belongs to this client.
                        // src_app_id is at bytes [32..64] of the wire payload.
                        let src_app_id_valid = if body.len() >= 64 {
                            let mut id = [0u8; 32];
                            id.copy_from_slice(&body[32..64]);
                            client_state.has_app_id(&id)
                        } else {
                            false // malformed — handle_ipc_send will drop it anyway
                        };
                        if !src_app_id_valid {
                            let mut hdr = FrameHeader::new(
                                FrameFamily::LocalApp as u8,
                                LocalAppMsg::AppSendFailed as u16,
                            );
                            hdr.body_len = 2;
                            let mut frame = veil_proto::codec::encode_header(&hdr).to_vec();
                            frame.extend_from_slice(&ipc_send_err::SPOOFED_SRC.to_be_bytes());
                            wh.write_all(&frame).await?;
                        } else {
                            let ctx = IpcSendContext {
                                app_registry:        &app_registry,
                                local_node_id:       &node_id,
                                session_tx_registry: session_tx_registry.as_deref(),
                                route_cache:         route_cache.as_deref(),
                                route_updated:       route_updated.as_deref(),
                                peer_mlkem_keys:     peer_mlkem_keys.as_deref(),
                                mlkem_ek_resolver:   mlkem_ek_resolver.as_deref(),
                                anon_onion_sender:   anon_onion_sender.as_deref(),
                                capture_tx:          capture_tx.as_deref(),
                                pending_recursive:   pending_recursive.as_deref(),
                                trace_sample_rate,
                                pending_ack:         pending_ack.as_deref(),
                            };
                            handle_ipc_send(&mut wh, &body, &ctx, &mut rate_limiter).await?;
                        }
                    }
                    Ok(LocalAppMsg::StreamOpen) => {
                        handle_stream_open(
                            &mut wh, &body, &mut client_state, &app_registry,
                            &stream_table, &node_id,
                            session_tx_registry.clone(), stream_bridge.as_ref(),
                        ).await?;
                    }
                    Ok(LocalAppMsg::StreamData) => {
                        if let Ok(p) = StreamDataPayload::decode(&body) {
                            // Route based on the client's role on this
                            // stream.  Opener (A) → forward to B endpoint;
                            // acceptor (B) → forward to A delivery channel.
                            // Cross-client hijack is closed by the
                            // ownership check itself: a frame from a
                            // client that is neither opener nor acceptor
                            // of `stream_id` is silently dropped.  Pre-fix
                            // only opener ownership was tracked, so every
                            // acceptor STREAM_DATA frame was dropped — the
                            // root cause of the "bidirectional stream that
                            // is actually one-way" bug (HIGH-1, audit
                            // batch 2026-05-23).
                            if client_state.owns_stream_as_opener(p.stream_id) {
                                if let Some(target) = stream_table.remote_route(p.stream_id) {
                                    // Remote-bound stream: forward as a wire
                                    // AppData frame to the destination node.
                                    // Session-level transport applies the
                                    // backpressure.
                                    let sent = if let Some(b) = session_tx_registry.as_deref() {
                                        crate::handlers::stream::send_app_data(
                                            b,
                                            &target.dst_node_id,
                                            target.wire_stream_id,
                                            target.app_id,
                                            target.endpoint_id,
                                            p.data,
                                        )
                                    } else {
                                        false
                                    };
                                    if !sent {
                                        // No live session to the destination: the
                                        // bytes cannot be delivered. Surface this
                                        // as a close instead of silently dropping
                                        // (the old behaviour) — drop the inbound
                                        // bridge registration so the parked
                                        // per-stream bridge task wakes, removes the
                                        // table entry and notifies this client with
                                        // STREAM_CLOSE (the same way a
                                        // remote-initiated close propagates). The
                                        // wire AppClose is pointless with no
                                        // session, so it is skipped.
                                        if let Some(bridge) = stream_bridge.as_ref() {
                                            bridge
                                                .veil_stream_rx
                                                .lock()
                                                .unwrap_or_else(|e| e.into_inner())
                                                .remove(&(
                                                    target.dst_node_id,
                                                    target.wire_stream_id,
                                                ));
                                        } else {
                                            // No bridge wired (should not happen for
                                            // a remote-bound stream): free the slot
                                            // directly.
                                            stream_table.close_remote(p.stream_id);
                                        }
                                        client_state.release_stream(p.stream_id);
                                    }
                                } else {
                                    let outcome = stream_table.route_data_from_a(p.stream_id, p.data);
                                    if matches!(
                                        outcome,
                                        crate::streams::RouteOutcome::PeerBackpressure
                                            | crate::streams::RouteOutcome::WindowExhausted
                                    ) {
                                        // `PeerBackpressure`: B's endpoint mpsc
                                        // returned `Full` (the route helper restores
                                        // the window before returning, so we are NOT
                                        // double-counting).
                                        //
                                        // `WindowExhausted` (cycle-7 H3): A overran
                                        // the send window the acceptor advertised.
                                        // The SDK never emits `STREAM_WINDOW` credit
                                        // refreshes, so the A→B budget only ever
                                        // shrinks; previously this arm ignored the
                                        // outcome and every further frame was
                                        // SILENTLY dropped while the stream stayed
                                        // open — breaking the reliable-stream
                                        // contract. Close so the loss surfaces as
                                        // EOF to A instead of vanishing.
                                        stream_table.close(p.stream_id);
                                        client_state.release_stream(p.stream_id);
                                    }
                                }
                            } else if client_state.owns_stream_as_acceptor(p.stream_id) {
                                if let Some(route) =
                                    client_state.acceptor_remote_route(p.stream_id)
                                {
                                    // Opener is on a REMOTE node: forward the reply
                                    // as a wire AppData frame to it (its node holds
                                    // the inbound bridge that delivers to its IPC
                                    // client). p.stream_id IS the wire stream id
                                    // (the acceptor saw it in STREAM_OPEN_INBOUND).
                                    if let Some(b) = session_tx_registry.as_deref() {
                                        crate::handlers::stream::send_app_data(
                                            b,
                                            &route.opener_node_id,
                                            p.stream_id,
                                            route.app_id,
                                            route.endpoint_id,
                                            p.data,
                                        );
                                    } else {
                                        // No session registry → can't reach the
                                        // opener; tear the stream down so the loss
                                        // surfaces rather than silently vanishing.
                                        stream_table.close(p.stream_id);
                                        client_state.release_stream(p.stream_id);
                                    }
                                } else {
                                    let outcome =
                                        stream_table.route_data_from_b(p.stream_id, p.data);
                                    if matches!(
                                        outcome,
                                        crate::streams::RouteOutcome::PeerBackpressure
                                    ) {
                                        stream_table.close(p.stream_id);
                                        client_state.release_stream(p.stream_id);
                                    }
                                }
                            }
                            // else: silent drop (cross-client hijack attempt).
                        }
                    }
                    Ok(LocalAppMsg::StreamClose) => {
                        if let Ok(p) = StreamClosePayload::decode(&body)
                            && (client_state.owns_stream_as_opener(p.stream_id)
                                || client_state.owns_stream_as_acceptor(p.stream_id))
                        {
                            // Acceptor of a REMOTE-opened stream: send the wire
                            // `AppClose` to the opener's node. `close_owned_stream`
                            // only knows OPENER-side remote routes (via the stream
                            // table); acceptor-side routes live on the client state,
                            // so without this the opener never learns the acceptor
                            // closed and leaks its wire-side stream. Read the route
                            // BEFORE `release_stream` drops it.
                            if let Some(route) = client_state.acceptor_remote_route(p.stream_id)
                                && let Some(b) = session_tx_registry.as_deref()
                            {
                                crate::handlers::stream::send_app_close(
                                    b,
                                    &route.opener_node_id,
                                    p.stream_id,
                                    route.app_id,
                                    route.endpoint_id,
                                );
                            }
                            // Ownership is checked above, so a guessed stream_id
                            // cannot close another client's (or another peer's)
                            // stream. `close_owned_stream` handles remote (wire
                            // `AppClose` + bridge teardown) vs local (notify both
                            // endpoints) — shared with the disconnect cleanup so
                            // explicit and implicit close behave identically.
                            close_owned_stream(
                                p.stream_id,
                                &stream_table,
                                session_tx_registry.as_deref(),
                                stream_bridge.as_ref(),
                            );
                            client_state.release_stream(p.stream_id);
                        }
                    }
                    Ok(LocalAppMsg::StreamWindow) => {
                        // STREAM_WINDOW from the acceptor (B) restores
                        // A's send-side budget; the opener cannot legally
                        // emit a window update (it has no "budget on the
                        // other side" to refresh).  Reject frames from
                        // opener clients so so that a compromised opener
                        // cannot inflate a stream's A→B credit beyond what
                        // the acceptor has actually committed to read.
                        if let Ok(p) = StreamWindowPayload::decode(&body)
                            && client_state.owns_stream_as_acceptor(p.stream_id) {
                                stream_table.window_update_from_b(p.stream_id, p.increment);
                            }
                    }
                    Ok(LocalAppMsg::AppRtSend) => {
                        // src_app_id is at bytes [32..64] of the wire payload (same offset as AppIpcSend).
                        let src_app_id_valid = if body.len() >= 64 {
                            let mut id = [0u8; 32];
                            id.copy_from_slice(&body[32..64]);
                            client_state.has_app_id(&id)
                        } else {
                            false
                        };
                        if !src_app_id_valid {
                            let err_code = ipc_send_err::SPOOFED_SRC.to_be_bytes();
                            let mut hdr = FrameHeader::new(FrameFamily::LocalApp as u8, LocalAppMsg::AppSendFailed as u16);
                            hdr.body_len = 2;
                            let mut frame = codec::encode_header(&hdr).to_vec();
                            frame.extend_from_slice(&err_code);
                            wh.write_all(&frame).await?;
                        } else {
                            handle_rt_send(
                                &mut wh,
                                &body,
                                session_tx_registry.as_deref(),
                                client_state.metrics.as_deref(),
                                &mut rate_limiter,
                            ).await?;
                        }
                    }
                    Ok(LocalAppMsg::AnycastResolve) => {
                        handle_anycast_resolve(&mut wh, &body, anycast_service.as_ref()).await?;
                    }
                    Ok(LocalAppMsg::AnycastAdvertise) => {
                        handle_anycast_advertise(&body, anycast_service.as_ref());
                    }
                    Ok(LocalAppMsg::AnycastWithdraw) => {
                        handle_anycast_withdraw(&body, anycast_service.as_ref());
                    }
                    Ok(LocalAppMsg::AnycastReportFailure) => {
                        handle_anycast_report_failure(&body, anycast_service.as_ref());
                    }
                    Ok(LocalAppMsg::RegisterOnionService) => {
                        use veil_proto::ipc::{RegisterOnionServicePayload, ipc_send_err};
                        // 0 = ok; else an ipc_send_err. Onion-service hosting goes
                        // through the same anon_onion_sender capability. Rate-limit
                        // (diff-audit D2): like the regular send path, gate the
                        // expensive circuit-build / DHT-publish work behind the
                        // per-connection token bucket.
                        let status: u16 = if rate_limiter.as_mut().is_some_and(|rl| !rl.allow()) {
                            ipc_send_err::RATE_LIMITED
                        } else if let Ok(p) = RegisterOnionServicePayload::decode(&body) {
                            match anon_onion_sender.as_deref() {
                                Some(s) => {
                                    match s.register_onion_service(p.hop_count as usize).await {
                                        Ok(()) => 0,
                                        Err(veil_types::AnonOnionSendError::NoRelays) => {
                                            ipc_send_err::NO_ROUTE
                                        }
                                        Err(veil_types::AnonOnionSendError::NoIdentity) => {
                                            ipc_send_err::NO_IDENTITY
                                        }
                                        Err(_) => ipc_send_err::NO_RENDEZVOUS,
                                    }
                                }
                                None => ipc_send_err::NO_RENDEZVOUS,
                            }
                        } else {
                            ipc_send_err::INVALID_FLAGS
                        };
                        let mut hdr = FrameHeader::new(
                            FrameFamily::LocalApp as u8,
                            LocalAppMsg::RegisterOnionServiceResult as u16,
                        );
                        hdr.body_len = 2;
                        let mut frame = codec::encode_header(&hdr).to_vec();
                        frame.extend_from_slice(&status.to_be_bytes());
                        wh.write_all(&frame).await?;
                    }
                    Ok(LocalAppMsg::RegisterRendezvousPublisher) => {
                        use veil_proto::ipc::{RegisterRendezvousPublisherPayload, ipc_send_err};
                        // Register a plain (sovereign-signed) rendezvous publisher
                        // advertising the relay's KEM key — mailbox-by-discovery.
                        // Rate-limit (D2): like the other register paths, gate the
                        // entry write behind the per-connection token bucket.
                        let status: u16 = if rate_limiter.as_mut().is_some_and(|rl| !rl.allow()) {
                            ipc_send_err::RATE_LIMITED
                        } else if let Ok(p) = RegisterRendezvousPublisherPayload::decode(&body) {
                            match anon_onion_sender.as_deref() {
                                Some(s) => {
                                    s.register_rendezvous_publisher(
                                        p.rendezvous_node_id,
                                        p.auth_cookie,
                                        p.validity_window_secs,
                                        p.relay_kem_algo,
                                        p.relay_kem_pk,
                                    );
                                    0
                                }
                                None => ipc_send_err::NO_RENDEZVOUS,
                            }
                        } else {
                            ipc_send_err::INVALID_FLAGS
                        };
                        let mut hdr = FrameHeader::new(
                            FrameFamily::LocalApp as u8,
                            LocalAppMsg::RegisterRendezvousPublisherResult as u16,
                        );
                        hdr.body_len = 2;
                        let mut frame = codec::encode_header(&hdr).to_vec();
                        frame.extend_from_slice(&status.to_be_bytes());
                        wh.write_all(&frame).await?;
                    }
                    Ok(LocalAppMsg::SendToOnionService) => {
                        use veil_proto::ipc::{SendToOnionServicePayload, ipc_send_err};
                        // 0 = ok; else an ipc_send_err. Resolving + sending to an
                        // onion service goes through the same anon_onion_sender.
                        // Rate-limit (D2) + src_app_id ownership (D1): match the old
                        // AppIpcSend path's protections, which the standalone arms
                        // previously skipped (diff-audit).
                        let status: u16 = if rate_limiter.as_mut().is_some_and(|rl| !rl.allow()) {
                            ipc_send_err::RATE_LIMITED
                        } else if let Ok(p) = SendToOnionServicePayload::decode(&body) {
                            // Only the anonymous variant delivers src_app_id as the
                            // sender's app identity, so only it needs the ownership
                            // check; the authenticated variant signs with the
                            // sovereign identity and carries no app-id claim.
                            if p.anonymous && !client_state.has_app_id(&p.src_app_id) {
                                ipc_send_err::SPOOFED_SRC
                            } else {
                                match anon_onion_sender.as_deref() {
                                    Some(s) => {
                                        // anonymous → service sees src=[0;32]; else
                                        // the daemon signs with our sovereign id.
                                        let send = if p.anonymous {
                                            s.send_to_onion_service_anonymous(
                                                p.service_identity_vk,
                                                p.target_app_id,
                                                p.target_endpoint_id,
                                                p.src_app_id,
                                                &p.data,
                                                p.hop_count as usize,
                                            )
                                            .await
                                        } else {
                                            s.send_to_onion_service(
                                                p.service_identity_vk,
                                                p.target_app_id,
                                                p.target_endpoint_id,
                                                &p.data,
                                                p.hop_count as usize,
                                            )
                                            .await
                                        };
                                        match send {
                                            Ok(()) => 0,
                                            Err(veil_types::AnonOnionSendError::NoRelays) => {
                                                ipc_send_err::NO_ROUTE
                                            }
                                            Err(veil_types::AnonOnionSendError::NoIdentity) => {
                                                ipc_send_err::NO_IDENTITY
                                            }
                                            Err(
                                                veil_types::AnonOnionSendError::PayloadTooLarge,
                                            ) => ipc_send_err::PAYLOAD_TOO_LARGE,
                                            // NoRendezvous → no resolvable/decryptable
                                            // descriptor for that identity.
                                            Err(_) => ipc_send_err::NO_RENDEZVOUS,
                                        }
                                    }
                                    None => ipc_send_err::NO_RENDEZVOUS,
                                }
                            }
                        } else {
                            ipc_send_err::INVALID_FLAGS
                        };
                        let mut hdr = FrameHeader::new(
                            FrameFamily::LocalApp as u8,
                            LocalAppMsg::SendToOnionServiceResult as u16,
                        );
                        hdr.body_len = 2;
                        let mut frame = codec::encode_header(&hdr).to_vec();
                        frame.extend_from_slice(&status.to_be_bytes());
                        wh.write_all(&frame).await?;
                    }
                    Ok(LocalAppMsg::SendAnonymousDirect) => {
                        use veil_proto::ipc::{SendAnonymousDirectPayload, ipc_send_err};
                        // 0 = ok; else an ipc_send_err. Direct sender-anonymous
                        // onion send to a known peer (no rendezvous).
                        // Rate-limit (D2) + src_app_id ownership (D1).
                        let status: u16 = if rate_limiter.as_mut().is_some_and(|rl| !rl.allow()) {
                            ipc_send_err::RATE_LIMITED
                        } else if let Ok(p) = SendAnonymousDirectPayload::decode(&body) {
                            // src_app_id is delivered as the sender's app identity;
                            // it must belong to this client.
                            if !client_state.has_app_id(&p.src_app_id) {
                                ipc_send_err::SPOOFED_SRC
                            } else {
                                match anon_onion_sender.as_deref() {
                                    Some(s) => {
                                        match s
                                            .send_anonymous_direct(
                                                p.target_node_id,
                                                p.target_x25519_pk,
                                                p.target_app_id,
                                                p.target_endpoint_id,
                                                p.src_app_id,
                                                &p.data,
                                                p.hop_count as usize,
                                            )
                                            .await
                                        {
                                            Ok(()) => 0,
                                            Err(veil_types::AnonOnionSendError::NoRelays) => {
                                                ipc_send_err::NO_ROUTE
                                            }
                                            Err(
                                                veil_types::AnonOnionSendError::PayloadTooLarge,
                                            ) => ipc_send_err::PAYLOAD_TOO_LARGE,
                                            Err(_) => ipc_send_err::NO_ROUTE,
                                        }
                                    }
                                    None => ipc_send_err::NO_ROUTE,
                                }
                            }
                        } else {
                            ipc_send_err::INVALID_FLAGS
                        };
                        let mut hdr = FrameHeader::new(
                            FrameFamily::LocalApp as u8,
                            LocalAppMsg::SendAnonymousDirectResult as u16,
                        );
                        hdr.body_len = 2;
                        let mut frame = codec::encode_header(&hdr).to_vec();
                        frame.extend_from_slice(&status.to_be_bytes());
                        wh.write_all(&frame).await?;
                    }
                    Ok(LocalAppMsg::TransportHintQuery) => {
                        handle_transport_hint_query(&mut wh, hint_registry.as_ref()).await?;
                    }
                    Ok(LocalAppMsg::SetMobileBackgroundMode) => {
                        handle_set_mobile_background_mode(&body, mobile_event_sink.as_ref());
                    }
                    Ok(LocalAppMsg::NetworkChanged) => {
                        handle_network_changed(&body, mobile_event_sink.as_ref());
                    }
                    Ok(LocalAppMsg::SetPushEnvelope) => {
                        handle_set_push_envelope(&mut wh, &body, push_envelope_sink.as_ref())
                            .await?;
                    }
                    Ok(LocalAppMsg::SetWakeHmacEnvelope) => {
                        handle_set_wake_hmac_envelope(
                            &mut wh,
                            &body,
                            push_envelope_sink.as_ref(),
                        )
                        .await?;
                    }
                    Ok(LocalAppMsg::MailboxPut) => {
                        handle_mailbox_put(
                            &mut wh,
                            &body,
                            &mut client_state,
                            mailbox_backend.as_ref(),
                        )
                        .await?;
                    }
                    Ok(LocalAppMsg::MailboxFetch) => {
                        handle_mailbox_fetch(
                            &mut wh,
                            &body,
                            &mut client_state,
                            mailbox_backend.as_ref(),
                        )
                        .await?;
                    }
                    Ok(LocalAppMsg::MailboxAck) => {
                        handle_mailbox_ack(
                            &mut wh,
                            &body,
                            &mut client_state,
                            mailbox_backend.as_ref(),
                        )
                        .await?;
                    }
                    Ok(LocalAppMsg::MailboxSeal) => {
                        handle_mailbox_seal(&mut wh, &body, mailbox_crypto_sink.as_ref()).await?;
                    }
                    Ok(LocalAppMsg::MailboxOpen) => {
                        handle_mailbox_open(&mut wh, &body, mailbox_crypto_sink.as_ref()).await?;
                    }
                    Ok(LocalAppMsg::OutboxPut) => {
                        handle_outbox_put(
                            &mut wh,
                            &body,
                            &mut client_state,
                            outbox_backend.as_ref(),
                        )
                        .await?;
                    }
                    Ok(LocalAppMsg::OutboxFindMissing) => {
                        handle_outbox_find_missing(
                            &mut wh,
                            &body,
                            &mut client_state,
                            outbox_backend.as_ref(),
                        )
                        .await?;
                    }
                    Ok(LocalAppMsg::OutboxAck) => {
                        handle_outbox_ack(&mut wh, &body, &mut client_state, outbox_backend.as_ref())
                            .await?;
                    }
                    Ok(LocalAppMsg::LookupRendezvousReplicas) => {
                        handle_lookup_rendezvous_replicas(
                            &mut wh,
                            &body,
                            &mut client_state,
                            rendezvous_resolver.as_ref(),
                        )
                        .await?;
                    }
                    Ok(LocalAppMsg::GetNodeIdentity) => {
                        handle_get_node_identity(
                            &mut wh,
                            &mut client_state,
                            node_id,
                            local_identity_algo,
                            &local_identity_pubkey,
                            local_relay_x25519_pubkey,
                        )
                        .await?;
                    }
                    Ok(LocalAppMsg::GetPeers) => {
                        handle_get_peers(&mut wh, &mut client_state, peer_list_provider.as_ref())
                            .await?;
                    }
                    Ok(LocalAppMsg::PnetStatusQuery) => {
                        crate::handlers::queries::handle_pnet_status_query(
                            &mut wh,
                            &body,
                            &mut client_state,
                            pnet_status_provider.as_ref(),
                        )
                        .await?;
                    }
                    Ok(LocalAppMsg::GetMobileStatus) => {
                        handle_get_mobile_status(
                            &mut wh,
                            &mut client_state,
                            mobile_status_provider.as_ref(),
                        )
                        .await?;
                    }
                    Ok(LocalAppMsg::JoinBootstrapUri) => {
                        handle_join_bootstrap_uri(
                            &mut wh,
                            &body,
                            &mut client_state,
                            bootstrap_join_sink.as_ref(),
                        )
                        .await?;
                    }
                    Ok(LocalAppMsg::CreateBootstrapInvite) => {
                        crate::handlers::queries::handle_create_bootstrap_invite(
                            &mut wh,
                            &body,
                            &mut client_state,
                            bootstrap_invite_create_sink.as_ref(),
                        )
                        .await?;
                    }
                    Ok(LocalAppMsg::PairSourceCreateInvite) => {
                        crate::handlers::queries::handle_pair_source_create_invite(
                            &mut wh,
                            &body,
                            &mut client_state,
                            pair_source_sink.as_ref(),
                        )
                        .await?;
                    }
                    Ok(LocalAppMsg::PairSourceHandleHello) => {
                        crate::handlers::queries::handle_pair_source_handle_hello(
                            &mut wh,
                            &body,
                            &mut client_state,
                            pair_source_sink.as_ref(),
                        )
                        .await?;
                    }
                    Ok(LocalAppMsg::PairSourceHandleConfirm) => {
                        crate::handlers::queries::handle_pair_source_handle_confirm(
                            &mut wh,
                            &body,
                            &mut client_state,
                            pair_source_sink.as_ref(),
                        )
                        .await?;
                    }
                    Ok(LocalAppMsg::PairTargetConsumeUri) => {
                        crate::handlers::queries::handle_pair_target_consume_uri(
                            &mut wh,
                            &body,
                            &mut client_state,
                            pair_target_sink.as_ref(),
                        )
                        .await?;
                    }
                    Ok(LocalAppMsg::PairTargetHandleCert) => {
                        crate::handlers::queries::handle_pair_target_handle_cert(
                            &mut wh,
                            &body,
                            &mut client_state,
                            pair_target_sink.as_ref(),
                        )
                        .await?;
                    }
                    Ok(LocalAppMsg::PairTargetBuildConfirm) => {
                        crate::handlers::queries::handle_pair_target_build_confirm(
                            &mut wh,
                            &body,
                            &mut client_state,
                            pair_target_sink.as_ref(),
                        )
                        .await?;
                    }
                    _ => {}
                }
            }

            // No traffic in EITHER direction for the idle window — close the
            // connection so its M6 semaphore permit is released (audit U3).
            () = &mut idle => {
                break;
            }
        }
    }

    // The read-half task (parked in `read_frame` awaiting the next client
    // frame) is aborted by the `_read_task` `AbortOnDrop` guard as this function
    // returns — on this `break`-driven path AND on any earlier `?` error-exit,
    // so a lingering read half never keeps the socket fd open (audit M4 / U3).

    // Close any streams this client still owns but never explicitly closed.
    // EOF / idle / write-error exits skip STREAM_CLOSE, so without this a
    // remote-bound stream leaks: its inbound bridge stays parked on `data_rx`,
    // its slot is held against MAX_TOTAL_STREAMS, and the peer keeps wire-side
    // state. Local pairs notify both endpoints; remotes emit a wire `AppClose`
    // + drop the bridge registration (see `close_owned_stream`). Idempotent, so
    // it is harmless for streams the client already closed explicitly.
    for stream_id in client_state.owned_stream_ids() {
        // Acceptor of a REMOTE-opened stream: notify the opener's node so it
        // doesn't leak its wire-side stream (close_owned_stream only covers
        // opener-side remote routes + local pairs). Mirrors the explicit-close
        // path above.
        if let Some(route) = client_state.acceptor_remote_route(stream_id)
            && let Some(b) = session_tx_registry.as_deref()
        {
            crate::handlers::stream::send_app_close(
                b,
                &route.opener_node_id,
                stream_id,
                route.app_id,
                route.endpoint_id,
            );
        }
        close_owned_stream(
            stream_id,
            &stream_table,
            session_tx_registry.as_deref(),
            stream_bridge.as_ref(),
        );
    }

    // client_state dropped here → all handles dropped → endpoints unregistered
    Ok(())
}

/// Generate a cryptographically random 16-byte client token.
///
/// The token is fed into BLAKE3 to derive the ephemeral `app_id` for this
/// client connection. Using `OsRng` (getrandom) prevents a local adversary
/// from predicting another process's app_id via time + PID enumeration.
fn generate_client_token() -> [u8; 16] {
    use rand_core::{OsRng, RngCore};
    let mut token = [0u8; 16];
    OsRng.fill_bytes(&mut token);
    token
}

// ── Tests ───────────────────────────────────────────────────────────────────

// Test bodies live in sibling files to keep this module focused on production
// code.  Unix tests use UnixStream / Permissions::mode (gated behind
// `cfg(unix)`); TCP backend tests are platform-agnostic and run cleanly via
// `--ignored` or on the dedicated Windows CI job.
#[cfg(all(test, unix))]
#[path = "server_tests_unix.rs"]
mod tests;

#[cfg(test)]
#[path = "server_tests_tcp.rs"]
mod tcp_backend_tests;

#[cfg(test)]
mod put_rate_limit_tests {
    use super::*;

    /// M-4: the delivery queue enforces a BYTE budget independent of the frame
    /// count cap — a slow/non-reading client cannot pin more than `max_bytes`,
    /// and draining a frame frees its bytes for the next enqueue.
    #[test]
    fn delivery_queue_byte_budget_binds_before_count() {
        // Generous count cap (100), tight byte budget (100 bytes).
        let (tx, mut rx, inflight) = delivery_queue(100, 100);
        let frame = || veil_bufpool::pooled_shared_from_vec(vec![0u8; 40]);
        assert!(tx.try_send(frame()).is_ok()); // 40 in flight
        assert!(tx.try_send(frame()).is_ok()); // 80 in flight
        // 80 + 40 = 120 > 100 → refused as Full even though only 2/100 slots used.
        assert!(matches!(
            tx.try_send(frame()),
            Err(mpsc::error::TrySendError::Full(_))
        ));
        assert_eq!(inflight.load(Ordering::Acquire), 80);
        // Drain one frame the way the socket-writer loop does → frees 40 bytes.
        let got = rx.try_recv().expect("a frame is queued");
        inflight.fetch_sub(got.len(), Ordering::AcqRel);
        assert_eq!(inflight.load(Ordering::Acquire), 40);
        // Budget is available again.
        assert!(tx.try_send(frame()).is_ok());
        assert_eq!(inflight.load(Ordering::Acquire), 80);
    }

    /// audit cycle-6 (A9): the per-client MailboxPut bucket allows up to
    /// `IPC_PUT_BURST` immediate puts, then denies until it refills — separate
    /// from the read-query bucket.
    #[test]
    fn allow_put_exhausts_burst_then_denies() {
        let (tx, _rx) = mpsc::channel::<veil_bufpool::PooledShared>(1);
        let mut st = IpcClientState::new(tx, [0u8; 32], [0u8; 16], None);

        // Drain the full burst.
        let mut allowed = 0u32;
        for _ in 0..IPC_PUT_BURST {
            if st.allow_put() {
                allowed += 1;
            }
        }
        assert_eq!(allowed, IPC_PUT_BURST, "full burst must be admitted");
        // Next put (no time elapsed → no refill) must be denied.
        assert!(!st.allow_put(), "put past the burst must be rate-limited");
        // The read-query bucket is independent and still full.
        assert!(
            st.allow_query(),
            "read-query bucket must be unaffected by puts"
        );
    }
}

#[cfg(all(test, unix))]
mod remote_stream_open_tests {
    use super::*;
    use crate::bridge::IpcStreamBridge;
    use crate::handlers::stream::handle_stream_open;
    use std::collections::HashMap;
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::AtomicU32;
    use tokio::net::UnixStream;
    use veil_proto::app::receipt_status;
    use veil_proto::{StreamOpenPayload, family::AppMsg};

    /// FrameBroadcaster that records every `send_to` so the test can inspect the
    /// `AppOpen` (and verify nothing else) the handler emits.
    #[derive(Default)]
    struct CapturingBroadcaster {
        sent: StdMutex<Vec<([u8; 32], Vec<u8>)>>,
    }
    impl veil_types::FrameBroadcaster for CapturingBroadcaster {
        fn send_to(&self, peer_id: &[u8; 32], _priority: u8, bytes: Vec<u8>) -> bool {
            self.sent.lock().unwrap().push((*peer_id, bytes));
            true
        }
        fn send_to_all_with_priority(&self, _priority: u8, _bytes: Arc<[u8]>) {}
        fn active_node_ids(&self) -> Vec<[u8; 32]> {
            Vec::new()
        }
    }

    fn fresh_bridge() -> IpcStreamBridge {
        IpcStreamBridge {
            veil_stream_rx: Arc::new(StdMutex::new(HashMap::new())),
            pending_receipts: Arc::new(StdMutex::new(HashMap::new())),
            // Start at 1 so the first wire stream-id is deterministically 1.
            wire_stream_counter: Arc::new(AtomicU32::new(1)),
        }
    }

    /// Drive a remote `STREAM_OPEN` through `handle_stream_open` with a mock
    /// broadcaster, completing the receipt for wire stream-id 1 with `status`.
    /// Returns the table + bridge + broadcaster for side-effect assertions.
    /// `_client` is returned (kept alive) so the reply write does not break-pipe.
    async fn run_open(
        status: u8,
    ) -> (
        IpcStreamTable,
        IpcStreamBridge,
        Arc<CapturingBroadcaster>,
        UnixStream,
    ) {
        run_open_on(IpcStreamTable::new(), status).await
    }

    /// As [`run_open`], but driving a caller-supplied table so a test can
    /// pre-fill it to capacity and exercise the post-accept `open_remote`-fails
    /// path (the remote already ACCEPTED, but we can't reserve a local id).
    async fn run_open_on(
        table: IpcStreamTable,
        status: u8,
    ) -> (
        IpcStreamTable,
        IpcStreamBridge,
        Arc<CapturingBroadcaster>,
        UnixStream,
    ) {
        let src = [0u8; 32];
        let dst = [9u8; 32];
        let bridge = fresh_bridge();
        let bc = Arc::new(CapturingBroadcaster::default());
        let registry = Arc::new(AppEndpointRegistry::new());
        let (delivery_tx, _delivery_rx) = mpsc::channel(8);
        let body = StreamOpenPayload {
            dst_node_id: dst,
            app_id: [5u8; 32],
            endpoint_id: 7,
            initial_window: 1024,
        }
        .encode();
        let (client, server) = UnixStream::pair().unwrap();
        let (_rh, wh) = veil_local_transport::LocalStream::Unix(server).into_split();

        let st_task = table.clone();
        let br_task = bridge.clone();
        let bc_task = Arc::clone(&bc);
        let task = tokio::spawn(async move {
            let mut cs = IpcClientState::new(delivery_tx, src, [0u8; 16], None);
            let mut wh = wh;
            handle_stream_open(
                &mut wh,
                &body,
                &mut cs,
                &registry,
                &st_task,
                &src,
                Some(bc_task as Arc<dyn veil_types::FrameBroadcaster>),
                Some(&br_task),
            )
            .await
            .unwrap();
        });

        // Complete the receipt for wire_stream_id == 1 once the handler has
        // registered it (no fixed sleep — yield until it appears).
        for _ in 0..10_000 {
            if let Some(tx) = bridge.pending_receipts.lock().unwrap().remove(&(dst, 1)) {
                let _ = tx.send(status);
                break;
            }
            tokio::task::yield_now().await;
        }
        task.await.unwrap();
        (table, bridge, bc, client)
    }

    #[tokio::test]
    async fn remote_open_accepted_registers_stream_and_sends_app_open() {
        let (table, bridge, bc, _client) = run_open(receipt_status::ACCEPTED).await;

        assert_eq!(table.len(), 1, "accepted open should register one stream");
        assert!(
            bridge
                .veil_stream_rx
                .lock()
                .unwrap()
                .contains_key(&([9u8; 32], 1)),
            "inbound bridge channel must stay registered after accept"
        );

        let sent = bc.sent.lock().unwrap();
        assert_eq!(sent.len(), 1, "exactly one AppOpen frame");
        assert_eq!(sent[0].0, [9u8; 32], "AppOpen must target dst_node_id");
        let hdr = veil_proto::codec::decode_header(&sent[0].1).unwrap();
        assert_eq!(hdr.msg_type, AppMsg::AppOpen as u16);
        assert_eq!(hdr.stream_id, 1, "AppOpen carries the allocated wire id");
    }

    #[tokio::test]
    async fn remote_open_rejected_cleans_up_registrations() {
        // A non-ACCEPTED status takes the rejection path (no 5 s timeout wait).
        let (table, bridge, bc, _client) = run_open(7).await;

        assert_eq!(table.len(), 0, "rejected open must not register a stream");
        assert!(
            bridge.veil_stream_rx.lock().unwrap().is_empty(),
            "inbound bridge channel must be deregistered on reject"
        );
        assert!(
            bridge.pending_receipts.lock().unwrap().is_empty(),
            "receipt waiter must be removed on reject"
        );
        assert_eq!(
            bc.sent.lock().unwrap().len(),
            1,
            "the AppOpen attempt still went out"
        );
    }

    /// Regression (audit 2026-06-03): when the remote has already ACCEPTED but
    /// the local table is at capacity (`open_remote` returns `None`), the daemon
    /// must send a wire `AppClose` to the peer so it does not leak the accepted
    /// half — on top of cleaning up its own registrations and replying
    /// `CAPACITY_REACHED` to the client.
    #[tokio::test]
    async fn remote_open_accepted_but_local_capacity_fail_sends_app_close() {
        // Pre-fill the table to capacity so the post-accept open_remote fails.
        let table = IpcStreamTable::new();
        for i in 0..veil_proto::budget::MAX_TOTAL_STREAMS as u32 {
            table
                .open_remote([0xCCu8; 32], i, [0u8; 32], 1)
                .expect("fill to capacity");
        }
        assert_eq!(table.len(), veil_proto::budget::MAX_TOTAL_STREAMS);

        let (table, bridge, bc, _client) = run_open_on(table, receipt_status::ACCEPTED).await;

        // No new stream reserved (still exactly at capacity); our own
        // registrations were cleaned up.
        assert_eq!(
            table.len(),
            veil_proto::budget::MAX_TOTAL_STREAMS,
            "capacity-fail must not add a stream"
        );
        assert!(
            bridge.veil_stream_rx.lock().unwrap().is_empty(),
            "inbound bridge channel must be deregistered on capacity-fail"
        );
        assert!(
            bridge.pending_receipts.lock().unwrap().is_empty(),
            "receipt waiter must be removed on capacity-fail"
        );

        // The peer that ACCEPTED must have received an AppClose (freeing its
        // wire-side state) — bc captured [AppOpen, AppClose] to dst [9u8; 32].
        let sent = bc.sent.lock().unwrap();
        let mut saw_open = false;
        let mut saw_close = false;
        for (peer, bytes) in sent.iter() {
            assert_eq!(*peer, [9u8; 32], "frames target the dst node");
            let hdr = veil_proto::codec::decode_header(bytes).unwrap();
            if hdr.msg_type == AppMsg::AppOpen as u16 {
                saw_open = true;
            }
            if hdr.msg_type == AppMsg::AppClose as u16 {
                saw_close = true;
            }
        }
        assert!(saw_open, "AppOpen still went out");
        assert!(
            saw_close,
            "capacity-fail after accept must AppClose the peer"
        );
    }

    /// `close_owned_stream` for a remote-bound stream — the per-stream teardown
    /// the disconnect-cleanup loop runs for every stream a vanishing client
    /// still owned — must: remove the table entry, emit a wire `AppClose` to the
    /// peer (freeing its wire-side state), and drop the inbound bridge
    /// registration so the parked bridge task winds down.
    #[test]
    fn close_owned_stream_remote_tears_down_table_bridge_and_appcloses_peer() {
        let table = IpcStreamTable::new();
        let bridge = fresh_bridge();
        let bc = Arc::new(CapturingBroadcaster::default());
        let dst = [9u8; 32];
        let wire_id = 1u32;

        let ipc_id = table
            .open_remote(dst, wire_id, [5u8; 32], 7)
            .expect("open_remote");
        let (data_tx, _data_rx) = mpsc::channel::<Vec<u8>>(1);
        bridge
            .veil_stream_rx
            .lock()
            .unwrap()
            .insert((dst, wire_id), data_tx);
        assert_eq!(table.len(), 1);

        super::close_owned_stream(
            ipc_id,
            &table,
            Some(&*bc as &dyn veil_types::FrameBroadcaster),
            Some(&bridge),
        );

        assert_eq!(table.len(), 0, "remote table entry must be removed");
        assert!(
            bridge.veil_stream_rx.lock().unwrap().is_empty(),
            "inbound bridge registration must be dropped"
        );
        let sent = bc.sent.lock().unwrap();
        assert_eq!(sent.len(), 1, "exactly one wire AppClose to the peer");
        assert_eq!(sent[0].0, dst, "AppClose targets the remote node");
        let hdr = veil_proto::codec::decode_header(&sent[0].1).unwrap();
        assert_eq!(hdr.msg_type, AppMsg::AppClose as u16);
        assert_eq!(
            hdr.stream_id, wire_id,
            "AppClose carries the wire stream id"
        );
    }
}
