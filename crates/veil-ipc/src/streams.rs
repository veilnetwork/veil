//! IPC stream table: maps active IPC streams between clients.
//!
//! An IPC stream is a bidirectional channel between two IPC clients (or an IPC
//! client and a remote veil peer). The table tracks all open streams and
//! routes STREAM_DATA and STREAM_CLOSE frames to the correct recipient.
//!
//! # Stream lifecycle
//!
//! 1. Client A sends `STREAM_OPEN { dst_node_id, app_id, endpoint_id }`.
//! 2. Node calls `IpcStreamTable::open_local` (for local endpoints):
//!    Allocates a `stream_id`.
//!    Pushes `AppMessage::StreamOpen` to client B's endpoint sender.
//!    Records the stream entry.
//! 3. Node replies `STREAM_OPEN_OK { stream_id }` to A.
//! 4. B's forwarder task converts `AppMessage::StreamOpen` → IPC `STREAM_OPEN` frame.
//! 5. STREAM_DATA from A → `route_data_from_a` → B's endpoint sender.
//! 6. STREAM_DATA from B → `route_data_from_b` → A's delivery channel.
//! 7. STREAM_CLOSE from either side → `close` → both sides get `STREAM_CLOSE`.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

use veil_app::registry::AppMessage;
use veil_proto::{
    FrameFamily, FrameHeader, LocalAppMsg, StreamClosePayload, StreamDataPayload, codec,
};

/// A2: maximum time a stream may sit idle (no STREAM_DATA in
/// either direction, no window updates) before the table reaps it. A
/// slow / unresponsive reader cannot pin an open `stream_id` forever
/// just by refusing to read AND refusing to send STREAM_CLOSE — the
/// watchdog forces close after this many seconds, freeing the entry
/// (and the `MAX_TOTAL_STREAMS` slot) regardless of cooperator behaviour.
///
/// 5 minutes balances "real long-poll / chat idle" (typical idle is
/// minutes between user keystrokes) vs "slow-reader DoS" (must not hold
/// arbitrarily many slots through inactivity). Caller-owned long-running
/// streams that legitimately go quiet should refresh activity via
/// `IpcStreamTable::touch` (e.g. an application-layer heartbeat) or
/// configure a higher cap via `set_idle_timeout`.
pub const DEFAULT_STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

// ── RouteOutcome ─────────────────────────────────────────────────────────────

/// Result of routing a STREAM_DATA frame.
///
/// Distinguishes between "route succeeded" (caller does nothing),
/// "no such stream" (caller drops the frame; pre-existing semantics —
/// stream may have just been reaped or closed), "window exhausted"
/// (caller should send a `STREAM_OPEN_ERR(WINDOW_EXHAUSTED)` reply or
/// close the stream), and "peer backpressure" (the receiver's mpsc is
/// full — caller MUST close the stream rather than silently dropping
/// data, because the window has already been debited and silently
/// losing the bytes would desync the sender's local view of how much
/// it has actually delivered).
///
/// Pre-fix, both `route_data_from_a` and `route_data_from_b` returned
/// a bare `bool` that the server.rs read loop ignored entirely.  The
/// window for A→B was already debited before the failed `try_send`, so
/// a sender that hit backpressure ON its peer's endpoint would
/// silently lose every frame and quietly exhaust its window with
/// nothing delivered.  The new contract: this method restores the
/// window on `PeerBackpressure` and returns the variant so the read
/// loop can close the stream cleanly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteOutcome {
    /// Data was enqueued for delivery.
    Sent,
    /// Stream `stream_id` is unknown (already-closed / reaped / never opened).
    UnknownStream,
    /// Sender's window did not have credit for the payload — frame
    /// rejected, no window change.
    WindowExhausted,
    /// Receiver's mpsc was full; the route helper has restored the
    /// window (no double-debit) and the caller should close the
    /// stream rather than retry, because silent drops would desync
    /// sender accounting.
    PeerBackpressure,
}

// ── StreamEntry ──────────────────────────────────────────────────────────────

struct StreamEntry {
    /// Delivery channel to notify client A (the opener).
    a_delivery_tx: crate::server::DeliveryQueueTx,
    /// Registry sender for client B's endpoint.
    b_endpoint_tx: mpsc::Sender<AppMessage>,
    /// Receive window: bytes A may still send to B.
    window_a_to_b: u32,
    /// A2: timestamp of the last observable stream activity
    /// (STREAM_DATA either direction, window update from B, or open).
    /// `reap_stale` evicts entries whose `last_activity + idle_timeout`
    /// is past the supplied `now`.
    last_activity: Instant,
}

// ── IpcStreamTable ───────────────────────────────────────────────────────────

/// Thread-safe table of active IPC streams.
///
/// Clone-cheap: inner state is behind `Arc<Mutex<_>>`.
#[derive(Clone, Default)]
pub struct IpcStreamTable {
    inner: std::sync::Arc<Mutex<IpcStreamTableInner>>,
}

/// A stream whose acceptor endpoint lives on a **remote** node.
///
/// The opener (client A) is local; the table only holds the outbound route +
/// identity. Outbound A→remote bytes are encoded as wire `AppData` frames by the
/// server dispatch loop; inbound remote→A bytes arrive via the per-stream bridge
/// task (registered in `veil_stream_rx`), not through this table.
struct RemoteStreamEntry {
    dst_node_id: [u8; 32],
    wire_stream_id: u32,
    app_id: [u8; 32],
    endpoint_id: u32,
    last_activity: Instant,
}

/// Outbound routing target for a remote-bound IPC stream — everything the
/// server needs to encode an `AppData`/`AppClose` wire frame for it.
#[derive(Debug, Clone, Copy)]
pub struct RemoteStreamTarget {
    pub dst_node_id: [u8; 32],
    pub wire_stream_id: u32,
    pub app_id: [u8; 32],
    pub endpoint_id: u32,
}

#[derive(Default)]
struct IpcStreamTableInner {
    streams: HashMap<u32, StreamEntry>,
    /// Cross-node streams keyed by the same IPC `stream_id` space as `streams`
    /// (both draw from `next_id`), so a client never sees a local and a remote
    /// stream collide on one id.
    remote_streams: HashMap<u32, RemoteStreamEntry>,
    next_id: u32,
}

impl IpcStreamTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Open a local stream between client A and a locally-registered endpoint B.
    ///
    /// * `a_delivery_tx` — write channel to client A's IPC socket loop.
    /// * `b_endpoint_tx` — registry sender for B's endpoint.
    /// * `initial_window` — receive window advertised by A (bytes B may send to A).
    ///
    /// Returns `Some(stream_id)` on success, or `None` when the global stream
    /// limit (`MAX_TOTAL_STREAMS`) has been reached.
    pub(crate) fn open_local(
        &self,
        a_delivery_tx: impl Into<crate::server::DeliveryQueueTx>,
        b_endpoint_tx: mpsc::Sender<AppMessage>,
        src_node_id: [u8; 32],
        initial_window: u32,
    ) -> Option<u32> {
        let a_delivery_tx = a_delivery_tx.into();
        // Clamp the peer-advertised window to a sane ceiling (defense-in-depth;
        // memory is already bounded by the per-endpoint channel). Clamping
        // never rejects a legitimate client, which advertises the 256 KiB
        // default — it only caps an absurd/hostile window. The clamped value
        // is what we both store AND advertise to B, so the two sides agree.
        let initial_window = initial_window.min(veil_proto::ipc::MAX_STREAM_INITIAL_WINDOW);
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        // Count BOTH tables against the global cap (matching `open_remote` and
        // `len()`). Checking only `streams` here let local opens push the
        // combined total past `MAX_TOTAL_STREAMS` whenever remote streams were
        // already holding slots — up to ~2× the intended ceiling.
        if inner.streams.len() + inner.remote_streams.len() >= veil_proto::budget::MAX_TOTAL_STREAMS
        {
            return None;
        }
        // Advance ID, skip any that collide with existing open streams.
        // The cap above guarantees ≥1 free ID exists in the u32 space, but
        // worst-case probing could in principle traverse the whole map.
        // Bound the search at `MAX_TOTAL_STREAMS + 1` so we never spin on
        // a corrupted state — and, crucially, return `None` on exhaustion
        // instead of silently overwriting an existing entry (which the
        // earlier `attempts < 1000` cutoff did when the table was packed
        // around `next_id`).
        let mut stream_id = inner.next_id.wrapping_add(1);
        let mut attempts = 0usize;
        let max_attempts = veil_proto::budget::MAX_TOTAL_STREAMS + 1;
        while inner.streams.contains_key(&stream_id)
            || inner.remote_streams.contains_key(&stream_id)
        {
            if attempts >= max_attempts {
                return None;
            }
            stream_id = stream_id.wrapping_add(1);
            attempts += 1;
        }
        inner.next_id = stream_id;

        // Notify B that a new stream has been opened to one of its endpoints.
        // If B's channel is full, reject the open — otherwise the stream becomes
        // a ghost: A gets STREAM_OPEN_OK but B never sees the notification.
        if b_endpoint_tx
            .try_send(AppMessage::StreamOpen {
                stream_id,
                src_node_id,
                initial_window,
            })
            .is_err()
        {
            return None;
        }

        inner.streams.insert(
            stream_id,
            StreamEntry {
                a_delivery_tx,
                b_endpoint_tx,
                window_a_to_b: initial_window,
                last_activity: Instant::now(),
            },
        );

        Some(stream_id)
    }

    /// Open a **remote**-bound stream: the opener (client A) is local, the
    /// acceptor endpoint `(app_id, endpoint_id)` lives on `dst_node_id`.
    ///
    /// Allocates an IPC `stream_id` from the same pool as [`Self::open_local`]
    /// (so ids never collide between local and remote) and records the outbound
    /// wire route. Returns `None` when the combined table is at
    /// `MAX_TOTAL_STREAMS`.
    ///
    /// The caller drives the wire `AppOpen` handshake and registers the inbound
    /// bridge in `veil_stream_rx`; this only reserves the id + outbound route.
    pub fn open_remote(
        &self,
        dst_node_id: [u8; 32],
        wire_stream_id: u32,
        app_id: [u8; 32],
        endpoint_id: u32,
    ) -> Option<u32> {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if inner.streams.len() + inner.remote_streams.len() >= veil_proto::budget::MAX_TOTAL_STREAMS
        {
            return None;
        }
        let mut stream_id = inner.next_id.wrapping_add(1);
        let mut attempts = 0usize;
        let max_attempts = veil_proto::budget::MAX_TOTAL_STREAMS + 1;
        while inner.streams.contains_key(&stream_id)
            || inner.remote_streams.contains_key(&stream_id)
        {
            if attempts >= max_attempts {
                return None;
            }
            stream_id = stream_id.wrapping_add(1);
            attempts += 1;
        }
        inner.next_id = stream_id;
        inner.remote_streams.insert(
            stream_id,
            RemoteStreamEntry {
                dst_node_id,
                wire_stream_id,
                app_id,
                endpoint_id,
                last_activity: Instant::now(),
            },
        );
        Some(stream_id)
    }

    /// If `stream_id` is remote-bound, refresh its activity timer and return the
    /// wire routing target so the caller can emit an `AppData` frame; otherwise
    /// `None` (caller falls back to local routing).
    pub fn remote_route(&self, stream_id: u32) -> Option<RemoteStreamTarget> {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let entry = inner.remote_streams.get_mut(&stream_id)?;
        entry.last_activity = Instant::now();
        Some(RemoteStreamTarget {
            dst_node_id: entry.dst_node_id,
            wire_stream_id: entry.wire_stream_id,
            app_id: entry.app_id,
            endpoint_id: entry.endpoint_id,
        })
    }

    /// Remove a remote-bound stream, returning its wire target so the caller can
    /// emit a final `AppClose`. Idempotent — `None` if already gone.
    pub fn close_remote(&self, stream_id: u32) -> Option<RemoteStreamTarget> {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let entry = inner.remote_streams.remove(&stream_id)?;
        Some(RemoteStreamTarget {
            dst_node_id: entry.dst_node_id,
            wire_stream_id: entry.wire_stream_id,
            app_id: entry.app_id,
            endpoint_id: entry.endpoint_id,
        })
    }

    /// Route STREAM_DATA from client A (opener) to client B (acceptor).
    ///
    /// On `PeerBackpressure` the window debit is rolled back so the
    /// caller's STREAM_WINDOW accounting stays consistent — see
    /// [`RouteOutcome`] for the full contract.
    pub fn route_data_from_a(&self, stream_id: u32, data: Vec<u8>) -> RouteOutcome {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let Some(entry) = inner.streams.get_mut(&stream_id) else {
            return RouteOutcome::UnknownStream;
        };
        let len = u32::try_from(data.len()).unwrap_or(u32::MAX);
        if entry.window_a_to_b < len {
            return RouteOutcome::WindowExhausted;
        }
        entry.window_a_to_b -= len;
        entry.last_activity = Instant::now();
        let msg = AppMessage::StreamData { stream_id, data };
        match entry.b_endpoint_tx.try_send(msg) {
            Ok(()) => RouteOutcome::Sent,
            Err(_) => {
                // Restore the window credit — the caller will close the
                // stream rather than retry, so the debit must not stick.
                entry.window_a_to_b = entry.window_a_to_b.saturating_add(len);
                RouteOutcome::PeerBackpressure
            }
        }
    }

    /// Route STREAM_DATA from client B (acceptor) to client A (opener).
    ///
    /// Pre-encodes the frame and pushes to A's delivery channel.  The
    /// B→A direction does not currently use windowing (the SDK reads
    /// off a bounded delivery_tx that propagates TCP backpressure all
    /// the way to A's IPC socket), so there is no window to restore on
    /// failure.  On `PeerBackpressure` the caller closes the stream so
    /// the sender's view tracks reality.
    pub fn route_data_from_b(&self, stream_id: u32, data: Vec<u8>) -> RouteOutcome {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let Some(entry) = inner.streams.get_mut(&stream_id) else {
            return RouteOutcome::UnknownStream;
        };
        entry.last_activity = Instant::now();
        let frame = encode_stream_data(stream_id, &data);
        match entry.a_delivery_tx.try_send(frame) {
            Ok(()) => RouteOutcome::Sent,
            Err(_) => RouteOutcome::PeerBackpressure,
        }
    }

    /// Apply a window update from B (increments A's send budget).
    pub fn window_update_from_b(&self, stream_id: u32, increment: u32) {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(entry) = inner.streams.get_mut(&stream_id) {
            // Bound the window at the same ceiling as the initial advertisement
            // so a stream of STREAM_WINDOW updates can't inflate the advisory
            // A→B flow-control counter past the cap.
            entry.window_a_to_b = entry
                .window_a_to_b
                .saturating_add(increment)
                .min(veil_proto::ipc::MAX_STREAM_INITIAL_WINDOW);
            entry.last_activity = Instant::now();
        }
    }

    /// A2: refresh `last_activity` for a long-lived but
    /// legitimately-idle stream (application-layer heartbeat hook).
    /// Caller is responsible for sending the actual heartbeat — this
    /// method only updates the watchdog timer. No-op if `stream_id`
    /// is unknown (already-reaped or never-opened).
    pub fn touch(&self, stream_id: u32) {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(entry) = inner.streams.get_mut(&stream_id) {
            entry.last_activity = Instant::now();
        }
    }

    /// A2: evict streams idle past `idle_timeout`. Returns
    /// the list of `stream_id`s that were closed; callers may surface
    /// them to metrics or operator logs. Each evicted stream goes
    /// through the full `close` path so both A and B receive
    /// `StreamClose` notifications.
    ///
    /// Intended caller: a periodic maintenance task in the IPC layer
    /// (e.g. every 60 s). Without this sweep, a slow-reader / silent-
    /// closer DoS could pin every `MAX_TOTAL_STREAMS` slot indefinitely.
    pub fn reap_stale(&self, idle_timeout: Duration) -> Vec<u32> {
        let now = Instant::now();
        let stale: Vec<u32> = {
            let inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            inner
                .streams
                .iter()
                .filter(|(_, e)| now.duration_since(e.last_activity) >= idle_timeout)
                .map(|(id, _)| *id)
                .collect()
        };
        for id in &stale {
            self.close(*id);
        }
        stale
    }

    /// A2 (remote companion to [`reap_stale`]): evict remote-bound streams idle
    /// past `idle_timeout`, returning each evicted stream's wire target so the
    /// caller can emit a final `AppClose` to the peer and drop the inbound bridge
    /// registration in `veil_stream_rx`.
    ///
    /// `reap_stale` sweeps only the local-pair `streams` map; remote-bound
    /// streams live in the sibling `remote_streams` map and — without this
    /// companion sweep — were never reaped at all, even though they count toward
    /// `len()` / `MAX_TOTAL_STREAMS`. A stream that broke without a STREAM_CLOSE
    /// (opener client vanished while its inbound bridge sits parked on
    /// `data_rx.recv()`) would otherwise leak its slot AND the peer's wire-side
    /// state indefinitely. Unlike `close`, this does not notify a local endpoint
    /// (the opener is, by construction of the stale case, gone or unresponsive);
    /// the returned targets drive the wire `AppClose` + bridge teardown.
    pub fn reap_stale_remote(&self, idle_timeout: Duration) -> Vec<RemoteStreamTarget> {
        let now = Instant::now();
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let stale: Vec<u32> = inner
            .remote_streams
            .iter()
            .filter(|(_, e)| now.duration_since(e.last_activity) >= idle_timeout)
            .map(|(id, _)| *id)
            .collect();
        stale
            .into_iter()
            .filter_map(|id| {
                inner
                    .remote_streams
                    .remove(&id)
                    .map(|e| RemoteStreamTarget {
                        dst_node_id: e.dst_node_id,
                        wire_stream_id: e.wire_stream_id,
                        app_id: e.app_id,
                        endpoint_id: e.endpoint_id,
                    })
            })
            .collect()
    }

    /// Close a stream. Notifies both A and B with STREAM_CLOSE.
    pub fn close(&self, stream_id: u32) {
        let Some(entry) = self
            .inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .streams
            .remove(&stream_id)
        else {
            return;
        };
        // Notify B via registry message.
        let _ = entry
            .b_endpoint_tx
            .try_send(AppMessage::StreamClose { stream_id });
        // Notify A via pre-encoded frame.
        let frame = encode_stream_close(stream_id);
        let _ = entry.a_delivery_tx.try_send(frame);
    }

    /// Number of currently open streams (local pairs + remote-bound).
    pub fn len(&self) -> usize {
        let inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        inner.streams.len() + inner.remote_streams.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ── Frame helpers ─────────────────────────────────────────────────────────────

pub(crate) fn encode_stream_data(stream_id: u32, data: &[u8]) -> veil_bufpool::PooledShared {
    let payload = StreamDataPayload {
        stream_id,
        data: data.to_vec(),
    };
    let body = payload.encode();
    let mut hdr = FrameHeader::new(FrameFamily::LocalApp as u8, LocalAppMsg::StreamData as u16);
    hdr.body_len = body.len() as u32;
    let hdr_bytes = codec::encode_header(&hdr);
    let mut p = veil_bufpool::global().acquire(hdr_bytes.len() + body.len());
    p.as_vec_mut().extend_from_slice(&hdr_bytes);
    p.as_vec_mut().extend_from_slice(&body);
    p.into_shared()
}

pub(crate) fn encode_stream_close(stream_id: u32) -> veil_bufpool::PooledShared {
    let payload = StreamClosePayload { stream_id };
    let body = payload.encode();
    let mut hdr = FrameHeader::new(FrameFamily::LocalApp as u8, LocalAppMsg::StreamClose as u16);
    hdr.body_len = body.len() as u32;
    let hdr_bytes = codec::encode_header(&hdr);
    let mut p = veil_bufpool::global().acquire(hdr_bytes.len() + body.len());
    p.as_vec_mut().extend_from_slice(&hdr_bytes);
    p.as_vec_mut().extend_from_slice(&body);
    p.into_shared()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use veil_app::registry::AppEndpointRegistry;

    fn node_id() -> [u8; 32] {
        [0x01u8; 32]
    }

    #[test]
    fn open_local_assigns_stream_id() {
        let table = IpcStreamTable::new();
        let registry = AppEndpointRegistry::new();
        let app_id = [0xAAu8; 32];
        let (_handle, _rx) = registry.register(app_id, 1, 8);
        let b_tx = registry.get_sender(app_id, 1).unwrap();
        let (a_tx, _a_rx) = mpsc::channel(1024);

        let id = table
            .open_local(a_tx, b_tx, node_id(), 65536)
            .expect("capacity not exceeded");
        assert!(id > 0);
        assert_eq!(table.len(), 1);
    }

    /// Regression (cycle-5 #1): `open_local` must count BOTH the local and
    /// remote stream tables against `MAX_TOTAL_STREAMS` (matching `open_remote`
    /// and `len()`). Before the fix it checked only the local table, so once
    /// remote streams had filled the global cap a local client could keep
    /// opening streams — pushing the combined total to ~2× the intended
    /// ceiling (memory / FD pressure).
    #[test]
    fn open_local_respects_combined_cap_with_remote_streams() {
        let table = IpcStreamTable::new();
        let dst = [7u8; 32];
        let app_id = [9u8; 32];
        // Saturate the entire global cap with remote-bound streams.
        for i in 0..veil_proto::budget::MAX_TOTAL_STREAMS as u32 {
            table
                .open_remote(dst, i, app_id, 1)
                .expect("remote opens succeed until the cap");
        }
        assert_eq!(table.len(), veil_proto::budget::MAX_TOTAL_STREAMS);

        // A local open must now be refused: the combined table is full even
        // though the local sub-table is still empty.
        let registry = AppEndpointRegistry::new();
        let local_app = [0xAAu8; 32];
        let (_handle, _rx) = registry.register(local_app, 1, 8);
        let b_tx = registry.get_sender(local_app, 1).unwrap();
        let (a_tx, _a_rx) = mpsc::channel(1024);
        assert!(
            table.open_local(a_tx, b_tx, node_id(), 65536).is_none(),
            "open_local must reject when remote streams already fill the cap"
        );
        assert_eq!(table.len(), veil_proto::budget::MAX_TOTAL_STREAMS);
    }

    #[test]
    fn route_data_from_b_delivers_to_a() {
        let table = IpcStreamTable::new();
        let registry = AppEndpointRegistry::new();
        let app_id = [0xBBu8; 32];
        let (_handle, _rx) = registry.register(app_id, 2, 8);
        let b_tx = registry.get_sender(app_id, 2).unwrap();
        let (a_tx, mut a_rx) = mpsc::channel(1024);

        let stream_id = table.open_local(a_tx, b_tx, node_id(), 65536).unwrap();

        assert_eq!(
            table.route_data_from_b(stream_id, b"hello".to_vec()),
            RouteOutcome::Sent
        );
        let frame = a_rx.try_recv().expect("A should have received a frame");
        // Verify it's a STREAM_DATA frame
        let hdr = codec::decode_header(&frame[..veil_proto::HEADER_SIZE]).unwrap();
        assert_eq!(hdr.msg_type, LocalAppMsg::StreamData as u16);
    }

    #[test]
    fn window_exhausted_blocks_a_to_b() {
        let table = IpcStreamTable::new();
        let registry = AppEndpointRegistry::new();
        let app_id = [0xCCu8; 32];
        let (_handle, mut b_rx) = registry.register(app_id, 3, 8);
        let b_tx = registry.get_sender(app_id, 3).unwrap();
        let (a_tx, _a_rx) = mpsc::channel(1024);

        let stream_id = table.open_local(a_tx, b_tx, node_id(), 10).unwrap(); // tiny window

        // 10 bytes fits
        assert_eq!(
            table.route_data_from_a(stream_id, vec![0u8; 10]),
            RouteOutcome::Sent
        );
        // 1 more byte doesn't
        assert_eq!(
            table.route_data_from_a(stream_id, vec![0u8; 1]),
            RouteOutcome::WindowExhausted
        );

        // Drain the StreamOpen message
        let _ = b_rx.try_recv();
        // Drain the StreamData
        let msg = b_rx.try_recv().unwrap();
        assert!(matches!(msg, AppMessage::StreamData { .. }));

        // Window update should restore capacity
        table.window_update_from_b(stream_id, 5);
        assert_eq!(
            table.route_data_from_a(stream_id, vec![0u8; 5]),
            RouteOutcome::Sent
        );
    }

    #[test]
    fn open_local_clamps_excessive_advertised_window() {
        let table = IpcStreamTable::new();
        let registry = AppEndpointRegistry::new();
        let app_id = [0xDDu8; 32];
        let (_handle, mut b_rx) = registry.register(app_id, 4, 8);
        let b_tx = registry.get_sender(app_id, 4).unwrap();
        let (a_tx, _a_rx) = mpsc::channel(1024);

        // A advertises an absurd window; it must be clamped to the cap both
        // in the StreamOpen notified to B and in the internal A→B counter.
        let _stream_id = table
            .open_local(a_tx, b_tx, node_id(), u32::MAX)
            .expect("capacity not exceeded");

        match b_rx.try_recv().expect("B should receive StreamOpen") {
            AppMessage::StreamOpen { initial_window, .. } => assert_eq!(
                initial_window,
                veil_proto::ipc::MAX_STREAM_INITIAL_WINDOW,
                "advertised window must be clamped to the cap"
            ),
            _ => panic!("expected StreamOpen message"),
        }
    }

    #[test]
    fn window_update_cannot_inflate_past_cap() {
        let table = IpcStreamTable::new();
        let registry = AppEndpointRegistry::new();
        let app_id = [0xEEu8; 32];
        let (_handle, _b_rx) = registry.register(app_id, 5, 8);
        let b_tx = registry.get_sender(app_id, 5).unwrap();
        let (a_tx, _a_rx) = mpsc::channel(1024);

        let stream_id = table.open_local(a_tx, b_tx, node_id(), 1024).unwrap();
        // A flood of huge window updates must not push the counter past the cap.
        table.window_update_from_b(stream_id, u32::MAX);
        table.window_update_from_b(stream_id, u32::MAX);
        // Sending exactly the cap succeeds; one more byte than the cap would
        // not be creditable, proving the window saturated at the ceiling.
        assert_eq!(
            table.route_data_from_a(
                stream_id,
                vec![0u8; veil_proto::ipc::MAX_STREAM_INITIAL_WINDOW as usize]
            ),
            RouteOutcome::Sent
        );
        assert_eq!(
            table.route_data_from_a(stream_id, vec![0u8; 1]),
            RouteOutcome::WindowExhausted
        );
    }

    /// Regression guard for the silent-data-loss bug.  Pre-fix a full
    /// b_endpoint_tx caused `try_send` to return `Err(Full)`; the
    /// caller saw `false` and assumed the route helper had already
    /// restored state, but the window had silently been debited.  The
    /// contract is now: on `PeerBackpressure` the window is restored,
    /// so retrying after a window-update or peer-drain would succeed
    /// against the same accounting state.
    #[tokio::test(flavor = "current_thread")]
    async fn route_from_a_backpressure_restores_window_and_signals() {
        let table = IpcStreamTable::new();
        let registry = AppEndpointRegistry::new();
        let app_id = [0xC1u8; 32];
        // Tiny endpoint receiver capacity (1) so we can saturate easily.
        let (_handle, mut b_rx) = registry.register(app_id, 30, 1);
        let b_tx = registry.get_sender(app_id, 30).unwrap();
        let (a_tx, _a_rx) = mpsc::channel(1024);

        // Window of 100 bytes — plenty.
        let stream_id = table.open_local(a_tx, b_tx, node_id(), 100).unwrap();

        // First send consumes the only slot (registry pushed StreamOpen
        // in `open_local`, which occupies the queue).  Second send
        // races the registry's StreamOpen — at least one of them must
        // backpressure.  Build a deterministic scenario by NOT draining
        // b_rx first.

        // Push enough to fill the receiver after StreamOpen is enqueued.
        // Capacity is 1, StreamOpen is already inside → next try_send
        // returns Full.
        let outcome = table.route_data_from_a(stream_id, vec![7u8; 5]);
        assert_eq!(
            outcome,
            RouteOutcome::PeerBackpressure,
            "saturated B receiver must surface PeerBackpressure, not be silently dropped"
        );

        // Window must be intact (the 5-byte debit was rolled back).
        // Drain the StreamOpen so we have capacity for a new frame.
        let _ = b_rx.try_recv();
        let after = table.route_data_from_a(stream_id, vec![7u8; 100]);
        assert_eq!(
            after,
            RouteOutcome::Sent,
            "full-window send after backpressure-rollback must succeed (window was not double-debited)"
        );
    }

    #[test]
    fn close_removes_stream_and_notifies_both() {
        let table = IpcStreamTable::new();
        let registry = AppEndpointRegistry::new();
        let app_id = [0xDDu8; 32];
        let (_handle, mut b_rx) = registry.register(app_id, 4, 8);
        let b_tx = registry.get_sender(app_id, 4).unwrap();
        let (a_tx, mut a_rx) = mpsc::channel(1024);

        let stream_id = table.open_local(a_tx, b_tx, node_id(), 65536).unwrap();
        table.close(stream_id);

        assert_eq!(table.len(), 0);

        // B gets StreamClose
        let _ = b_rx.try_recv(); // StreamOpen
        let msg = b_rx.try_recv().unwrap();
        assert!(matches!(msg, AppMessage::StreamClose { .. }));

        // A gets STREAM_CLOSE frame
        let frame = a_rx.try_recv().unwrap();
        let hdr = codec::decode_header(&frame[..veil_proto::HEADER_SIZE]).unwrap();
        assert_eq!(hdr.msg_type, LocalAppMsg::StreamClose as u16);
    }

    /// A2: idle stream past the watchdog horizon must be reaped.
    /// Manipulates `last_activity` directly to simulate a 5-minute idle
    /// without sleeping the test.
    #[test]
    fn reap_stale_evicts_idle_streams_only() {
        let table = IpcStreamTable::new();
        let registry = AppEndpointRegistry::new();
        let app_id = [0xEEu8; 32];
        let (_handle, _rx) = registry.register(app_id, 5, 8);
        let b_tx = registry.get_sender(app_id, 5).unwrap();
        let (a_tx, _a_rx) = mpsc::channel(1024);

        let idle_id = table
            .open_local(a_tx.clone(), b_tx.clone(), node_id(), 1024)
            .unwrap();
        let active_id = table.open_local(a_tx, b_tx, node_id(), 1024).unwrap();

        // Backdate the idle stream's activity to 10 min ago.
        {
            let mut inner = table.inner.lock().unwrap();
            inner.streams.get_mut(&idle_id).unwrap().last_activity =
                Instant::now() - Duration::from_secs(600);
        }
        // Active stream stays fresh.

        let reaped = table.reap_stale(Duration::from_secs(300));
        assert_eq!(reaped, vec![idle_id]);
        assert!(
            table.inner.lock().unwrap().streams.contains_key(&active_id),
            "fresh stream must NOT be reaped"
        );
        assert!(
            !table.inner.lock().unwrap().streams.contains_key(&idle_id),
            "stale stream must be removed"
        );
    }

    /// `touch` resets the watchdog so an application heartbeat can keep
    /// a deliberately-idle long-poll alive past the default 5-min cap.
    #[test]
    fn touch_refreshes_watchdog() {
        let table = IpcStreamTable::new();
        let registry = AppEndpointRegistry::new();
        let app_id = [0xFFu8; 32];
        let (_handle, _rx) = registry.register(app_id, 6, 8);
        let b_tx = registry.get_sender(app_id, 6).unwrap();
        let (a_tx, _a_rx) = mpsc::channel(1024);

        let stream_id = table.open_local(a_tx, b_tx, node_id(), 1024).unwrap();

        // Backdate to 10 min ago, then touch — should NOT be reaped.
        {
            let mut inner = table.inner.lock().unwrap();
            inner.streams.get_mut(&stream_id).unwrap().last_activity =
                Instant::now() - Duration::from_secs(600);
        }
        table.touch(stream_id);

        let reaped = table.reap_stale(Duration::from_secs(300));
        assert!(
            reaped.is_empty(),
            "touched stream should not be reaped; got {reaped:?}"
        );
    }

    // ── Remote-bound streams (cross-node IPC forwarding) ─────────────────────

    #[test]
    fn open_remote_routes_then_closes() {
        let table = IpcStreamTable::new();
        let dst = [7u8; 32];
        let app_id = [9u8; 32];
        let id = table.open_remote(dst, 100, app_id, 5).expect("open_remote");

        // `remote_route` yields the wire target for outbound AppData.
        let target = table.remote_route(id).expect("remote_route");
        assert_eq!(target.dst_node_id, dst);
        assert_eq!(target.wire_stream_id, 100);
        assert_eq!(target.app_id, app_id);
        assert_eq!(target.endpoint_id, 5);
        assert_eq!(table.len(), 1);

        // `close_remote` removes the entry and returns the target once; a second
        // close is a no-op (idempotent), and the stream no longer routes.
        let closed = table.close_remote(id).expect("close_remote");
        assert_eq!(closed.wire_stream_id, 100);
        assert!(table.close_remote(id).is_none());
        assert!(table.remote_route(id).is_none());
        assert_eq!(table.len(), 0);
    }

    /// Regression (audit 2026-06-03): remote-bound streams must be swept by the
    /// idle reaper too — before `reap_stale_remote` they lived in a sibling map
    /// that `reap_stale` never touched, so an orphaned remote stream leaked its
    /// `MAX_TOTAL_STREAMS` slot forever. The sweep returns the wire targets so
    /// the server can emit a final `AppClose` to each peer.
    #[test]
    fn reap_stale_remote_evicts_idle_remote_streams_and_returns_targets() {
        let table = IpcStreamTable::new();
        let dst = [0x33u8; 32];
        let app_id = [0x44u8; 32];
        let idle_id = table
            .open_remote(dst, 700, app_id, 5)
            .expect("open_remote idle");
        let active_id = table
            .open_remote([0x99u8; 32], 800, app_id, 6)
            .expect("open_remote active");
        assert_eq!(table.len(), 2);

        // Backdate the idle remote stream's activity to 10 min ago.
        {
            let mut inner = table.inner.lock().unwrap();
            inner
                .remote_streams
                .get_mut(&idle_id)
                .unwrap()
                .last_activity = Instant::now() - Duration::from_secs(600);
        }

        let reaped = table.reap_stale_remote(Duration::from_secs(300));
        assert_eq!(reaped.len(), 1, "exactly one idle remote stream reaped");
        assert_eq!(reaped[0].wire_stream_id, 700);
        assert_eq!(reaped[0].dst_node_id, dst);
        // Idle entry gone; fresh entry retained; slot freed.
        assert!(
            table.close_remote(idle_id).is_none(),
            "idle remote stream already removed by the sweep"
        );
        assert!(
            table.remote_route(active_id).is_some(),
            "fresh remote stream must NOT be reaped"
        );
    }

    #[test]
    fn local_and_remote_ids_never_collide() {
        let table = IpcStreamTable::new();
        let (a_tx, _a_rx) = mpsc::channel(64);
        let mut keep_b = Vec::new();
        let mut local_ids = Vec::new();
        let mut remote_ids = Vec::new();
        for i in 0..40u32 {
            if i % 2 == 0 {
                // Local pair — keep the B receiver alive so `open_local`'s
                // StreamOpen notification `try_send` succeeds.
                let (b_tx, b_rx) = mpsc::channel(8);
                keep_b.push(b_rx);
                local_ids.push(
                    table
                        .open_local(a_tx.clone(), b_tx, node_id(), 1024)
                        .unwrap(),
                );
            } else {
                remote_ids.push(table.open_remote([i as u8; 32], i, [0u8; 32], i).unwrap());
            }
        }
        // Every id (local + remote) is unique — they share one allocator.
        let all: std::collections::HashSet<u32> =
            local_ids.iter().chain(&remote_ids).copied().collect();
        assert_eq!(all.len(), 40);
        assert_eq!(table.len(), 40);
        // `remote_route` discriminates remote from local streams.
        for id in &remote_ids {
            assert!(
                table.remote_route(*id).is_some(),
                "remote {id} should route"
            );
        }
        for id in &local_ids {
            assert!(
                table.remote_route(*id).is_none(),
                "local {id} must not remote-route"
            );
        }
    }
}
