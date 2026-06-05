//! Veil stream connector for the SOCKS5 ingress proxy.
//!
//! `VeilConnector` implements [`ProxyConnector`] by opening an veil
//! application stream to the exit node via the OVL1 app layer (APP_OPEN /
//! APP_DATA / APP_CLOSE). It is used by [`Socks5Proxy`] to route proxied
//! TCP streams through the veil network.
//!
//! # Protocol flow
//!
//! ```text
//! SOCKS5 client
//! ↓ CONNECT request
//! Socks5Proxy (local node)
//! ↓ VeilConnector::connect
//! 1. APP_OPEN → exit node (veil session)
//! 2. Wait for APP_RECEIPT_ACCEPTED
//! 3. Write proxy-connect header as first APP_DATA
//! 4. Return VeilBiStream that bridges duplex ↔ veil frames
//! ↓ veil ↕ frames
//! Exit node
//! ↓ handle_proxy_connect_stream
//! ↓ TCP connection to final destination
//! ```

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU32, AtomicUsize, Ordering},
    },
};

use async_trait::async_trait;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{mpsc, oneshot},
    time::{Duration, timeout},
};

use veil_proto::{
    app::{AppClosePayload, AppDataPayload, AppOpenPayload, close_reason},
    codec::encode_header,
    family::{AppMsg, FrameFamily},
    header::{FrameHeader, priority},
};
use veil_types::FrameBroadcaster;

use crate::exit::encode_proxy_header;
use crate::socks5::{BiStream, ProxyConnector, ProxyDestination, Socks5Error};

// ── Type aliases ─────────────────────────────────────────────────────────────

/// Map: `stream_id → receipt waiter` for locally-initiated veil streams.
pub type PendingReceiptMap = Arc<Mutex<HashMap<u32, oneshot::Sender<u8>>>>;

/// Map: `(peer_id, stream_id) → byte channel` for inbound stream data routing.
pub type VeilStreamRxMap = Arc<Mutex<HashMap<([u8; 32], u32), mpsc::Sender<Vec<u8>>>>>;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Well-known exit proxy app_id: all bytes 0xEE.
///
/// Exit nodes register this app_id in their `AppEndpointRegistry` to
/// receive incoming proxy-connect streams.
pub const EXIT_PROXY_APP_ID: [u8; 32] = [0xEE; 32];

/// Exit proxy endpoint ID.
pub const EXIT_PROXY_ENDPOINT_ID: u32 = 0;

/// Timeout for the APP_RECEIPT_ACCEPTED handshake.
const OPEN_RECEIPT_TIMEOUT: Duration = Duration::from_secs(10);

/// per-bridge duplex buffer size — pulled from
/// `veil_proto::budget::PROXY_DUPLEX_BUF_SIZE`. Was 256 KiB locally;
/// reduced to 64 KiB to bound aggregate memory at 256 × 64 KiB = 16 MiB
/// instead of 128 MiB on a fully-loaded relay. Matches wire frame
/// sizing — one APP_DATA chunk fits in the pipe with headroom.
const DUPLEX_BUF_SIZE: usize = veil_proto::budget::PROXY_DUPLEX_BUF_SIZE;

// ── VeilConnector ──────────────────────────────────────────────────────────

/// Connects SOCKS5 clients to exit nodes via veil application streams.
///
/// Clone-cheap: all fields are `Arc`.
#[derive(Clone)]
pub struct VeilConnector {
    /// Outbound frame sink — used to send APP_OPEN / APP_DATA / APP_CLOSE frames.
    /// trait-typed adapter (`SessionTxBroadcaster` in production).
    broadcaster: Arc<dyn FrameBroadcaster>,
    /// Local node id — used to populate frame fields.
    local_node_id: [u8; 32],
    /// Monotonic stream-id counter.
    stream_counter: Arc<AtomicU32>,
    /// Shared with the dispatcher: pending receipt waiters.
    pending_receipts: PendingReceiptMap,
    /// Shared with the dispatcher: stream data channels.
    veil_stream_rx: VeilStreamRxMap,
    /// shared count of currently-active proxy
    /// bridges. Incremented on `connect` success, decremented when
    /// the wrapping `VeilBiStream` (or its bridge guard) drops.
    /// Caps memory usage by refusing new bridges past
    /// `MAX_PROXY_BRIDGES`.
    active_bridges: Arc<AtomicUsize>,
}

impl VeilConnector {
    pub fn new(
        broadcaster: Arc<dyn FrameBroadcaster>,
        _exit_node_id: [u8; 32], // kept for API symmetry; the actual exit_node_id comes from ProxyConnector::connect
        local_node_id: [u8; 32],
        pending_receipts: PendingReceiptMap,
        veil_stream_rx: VeilStreamRxMap,
        // Shared across every surface that opens wire streams on this node (the
        // IPC remote-stream path + this connector) so `(node_id, stream_id)`
        // keys never collide between surfaces. See `veil_ipc::bridge`.
        stream_counter: Arc<AtomicU32>,
    ) -> Self {
        Self {
            broadcaster,
            local_node_id,
            stream_counter,
            pending_receipts,
            veil_stream_rx,
            active_bridges: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// current number of active proxy bridges.
    /// Exposed for metrics + ops visibility.
    pub fn active_bridges(&self) -> usize {
        self.active_bridges.load(Ordering::Relaxed)
    }
}

/// RAII slot reservation in the global proxy
/// budget. Holding one of these counts as one active bridge; dropping
/// it releases the slot.
struct BridgeSlot {
    counter: Arc<AtomicUsize>,
}

impl BridgeSlot {
    /// Try to reserve one bridge slot. Returns `Some` on success, or
    /// `None` when the global budget is exhausted.
    fn try_acquire(counter: Arc<AtomicUsize>) -> Option<Self> {
        // Compare-and-swap loop guarantees the increment never crosses
        // the cap even with many concurrent acquires.
        loop {
            let cur = counter.load(Ordering::Acquire);
            if cur >= veil_proto::budget::MAX_PROXY_BRIDGES {
                return None;
            }
            match counter.compare_exchange(cur, cur + 1, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return Some(Self { counter }),
                Err(_) => continue,
            }
        }
    }
}

impl Drop for BridgeSlot {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::AcqRel);
    }
}

#[async_trait]
impl ProxyConnector for VeilConnector {
    async fn connect(
        &self,
        exit_node_id: [u8; 32],
        destination: &ProxyDestination,
    ) -> Result<Box<dyn BiStream>, Socks5Error> {
        // reserve one slot in the global bridge
        // budget BEFORE allocating any per-stream resources. Slot is
        // released when the wrapping `VeilBiStream` (and the
        // returned task's owned copy) drops.
        let bridge_slot =
            BridgeSlot::try_acquire(Arc::clone(&self.active_bridges)).ok_or_else(|| {
                Socks5Error::ConnectFailed(format!(
                    "proxy bridge budget exhausted (cap = {})",
                    veil_proto::budget::MAX_PROXY_BRIDGES,
                ))
            })?;
        let stream_id = self.stream_counter.fetch_add(1, Ordering::Relaxed);

        // Register receipt waiter before sending APP_OPEN to avoid a race.
        let (receipt_tx, receipt_rx) = oneshot::channel::<u8>();
        self.pending_receipts
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(stream_id, receipt_tx);

        // Register the inbound data channel.
        let (data_tx, data_rx) =
            mpsc::channel::<Vec<u8>>(veil_proto::budget::PROXY_STREAM_CHANNEL_CAP);
        self.veil_stream_rx
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert((exit_node_id, stream_id), data_tx);

        // Send APP_OPEN to the exit node.
        let open_payload = AppOpenPayload {
            app_id: EXIT_PROXY_APP_ID,
            endpoint_id: EXIT_PROXY_ENDPOINT_ID,
            flags: 0,
        };
        let body = open_payload.encode();
        let mut hdr = FrameHeader::new(FrameFamily::App as u8, AppMsg::AppOpen as u16);
        hdr.body_len = body.len() as u32;
        hdr.stream_id = stream_id;
        hdr.set_priority(priority::INTERACTIVE);
        let mut frame = encode_header(&hdr).to_vec();
        frame.extend_from_slice(&body);

        let sent = self
            .broadcaster
            .send_to(&exit_node_id, priority::INTERACTIVE, frame);
        if !sent {
            // Clean up registrations.
            self.pending_receipts
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&stream_id);
            self.veil_stream_rx
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&(exit_node_id, stream_id));
            return Err(Socks5Error::ConnectFailed(
                "no session to exit node".to_owned(),
            ));
        }

        // Wait for APP_RECEIPT_ACCEPTED from the exit node.
        let status = timeout(OPEN_RECEIPT_TIMEOUT, receipt_rx)
            .await
            .map_err(|_| {
                self.veil_stream_rx
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .remove(&(exit_node_id, stream_id));
                Socks5Error::ConnectFailed("APP_OPEN receipt timeout".to_owned())
            })?
            .map_err(|_| {
                self.veil_stream_rx
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .remove(&(exit_node_id, stream_id));
                Socks5Error::ConnectFailed("APP_OPEN receipt sender dropped".to_owned())
            })?;

        use veil_proto::app::receipt_status;
        if status != receipt_status::ACCEPTED {
            self.veil_stream_rx
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&(exit_node_id, stream_id));
            return Err(Socks5Error::ConnectFailed(format!(
                "APP_OPEN rejected (status=0x{status:04x})"
            )));
        }

        // Create the bidirectional pipe.
        let (user_half, inner_half) = tokio::io::duplex(DUPLEX_BUF_SIZE);

        // Send the proxy-connect header as the first outbound APP_DATA.
        let proxy_header = encode_proxy_header(&destination.host, destination.port);

        // Spawn the bridge task that connects the duplex to the veil frame stream.
        let broadcaster = Arc::clone(&self.broadcaster);
        let veil_stream_rx_map = Arc::clone(&self.veil_stream_rx);
        let local_node_id = self.local_node_id;
        tokio::spawn(run_client_bridge(
            inner_half,
            data_rx,
            exit_node_id,
            stream_id,
            local_node_id,
            broadcaster,
            veil_stream_rx_map,
            proxy_header,
        ));

        Ok(Box::new(VeilBiStream {
            inner: user_half,
            _slot: bridge_slot,
        }))
    }
}

// ── VeilBiStream ───────────────────────────────────────────────────────────

/// Wraps a `tokio::io::DuplexStream` as a [`BiStream`].
///
/// holds [`BridgeSlot`] RAII guard so the
/// global proxy-bridge counter is decremented when the SOCKS5 client
/// closes the connection (whichever side drops the stream first).
struct VeilBiStream {
    inner: tokio::io::DuplexStream,
    _slot: BridgeSlot,
}

impl BiStream for VeilBiStream {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn tokio::io::AsyncRead + Send + Unpin>,
        Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
    ) {
        // keep the slot alive for the longer-
        // living half of the duplex. We attach it to the read half
        // by wrapping it in `VeilBiStreamHalf`.
        let (r, w) = tokio::io::split(self.inner);
        let read = VeilBiStreamReadHalf {
            inner: r,
            _slot: self._slot,
        };
        (Box::new(read), Box::new(w))
    }
}

/// read-half wrapper that keeps the bridge slot
/// alive until the SOCKS5 read direction closes — at which point the
/// underlying TCP stream is also done in practice.
struct VeilBiStreamReadHalf {
    inner: tokio::io::ReadHalf<tokio::io::DuplexStream>,
    _slot: BridgeSlot,
}

impl tokio::io::AsyncRead for VeilBiStreamReadHalf {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

// ── Client-side bridge task ───────────────────────────────────────────────────

/// Bridges the duplex inner half to/from veil APP_DATA frames.
///
/// # Outbound (duplex → veil)
/// Reads bytes from `inner_half` and sends them as `APP_DATA` frames.
///
/// # Inbound (veil → duplex)
/// Receives byte vectors from `data_rx` (fed by the dispatcher) and writes
/// them to `inner_half`.
#[allow(clippy::too_many_arguments)]
async fn run_client_bridge(
    inner_half: tokio::io::DuplexStream,
    mut data_rx: mpsc::Receiver<Vec<u8>>,
    peer_id: [u8; 32],
    stream_id: u32,
    _local_node_id: [u8; 32],
    broadcaster: Arc<dyn FrameBroadcaster>,
    veil_stream_rx_map: VeilStreamRxMap,
    initial_data: Vec<u8>,
) {
    let (mut ir, mut iw) = tokio::io::split(inner_half);

    // ── Inbound: veil → duplex write ──────────────────────────────────────
    let iw_task = tokio::spawn(async move {
        while let Some(data) = data_rx.recv().await {
            if iw.write_all(&data).await.is_err() {
                break;
            }
        }
    });

    // ── Outbound: duplex read → veil APP_DATA ──────────────────────────────
    // Send the initial proxy-connect header first.
    if !initial_data.is_empty() {
        send_app_data(broadcaster.as_ref(), &peer_id, stream_id, &initial_data);
    }

    let mut buf = vec![0u8; 65536];
    loop {
        let n = match ir.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        if !send_app_data(broadcaster.as_ref(), &peer_id, stream_id, &buf[..n]) {
            break;
        }
    }

    // Clean up the inbound channel map entry.
    veil_stream_rx_map
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(&(peer_id, stream_id));

    // Send APP_CLOSE.
    send_app_close(broadcaster.as_ref(), &peer_id, stream_id);

    iw_task.abort();
}

// ── Frame encoding helpers ────────────────────────────────────────────────────

/// Encode and send an APP_DATA frame. Returns `false` if the session is gone.
fn send_app_data(
    broadcaster: &dyn FrameBroadcaster,
    peer_id: &[u8; 32],
    stream_id: u32,
    data: &[u8],
) -> bool {
    let payload = AppDataPayload {
        app_id: EXIT_PROXY_APP_ID,
        endpoint_id: EXIT_PROXY_ENDPOINT_ID,
        seq: 0, // ordering maintained by the underlying session transport
        data: data.to_vec(),
    };
    let body = payload.encode();
    let mut hdr = FrameHeader::new(FrameFamily::App as u8, AppMsg::AppData as u16);
    hdr.body_len = body.len() as u32;
    hdr.stream_id = stream_id;
    hdr.set_priority(priority::INTERACTIVE);
    let mut frame = encode_header(&hdr).to_vec();
    frame.extend_from_slice(&body);
    broadcaster.send_to(peer_id, priority::INTERACTIVE, frame)
}

/// Encode and send an APP_CLOSE frame.
fn send_app_close(broadcaster: &dyn FrameBroadcaster, peer_id: &[u8; 32], stream_id: u32) {
    let payload = AppClosePayload {
        app_id: EXIT_PROXY_APP_ID,
        endpoint_id: EXIT_PROXY_ENDPOINT_ID,
        reason: close_reason::NORMAL,
    };
    let body = payload.encode();
    let mut hdr = FrameHeader::new(FrameFamily::App as u8, AppMsg::AppClose as u16);
    hdr.body_len = body.len() as u32;
    hdr.stream_id = stream_id;
    hdr.set_priority(priority::INTERACTIVE);
    let mut frame = encode_header(&hdr).to_vec();
    frame.extend_from_slice(&body);
    broadcaster.send_to(peer_id, priority::INTERACTIVE, frame);
}

// ── Server-side bridge task (exit node) ──────────────────────────────────────

/// Bridge task for the exit-proxy server side.
///
/// Created by the exit-proxy accept loop when a `StreamOpen` event arrives.
/// Bridges an in-process duplex pipe half to the veil APP_DATA frames.
///
/// # Inbound (veil → duplex write)
/// `data_rx` receives byte vectors fed by the exit proxy accept loop
/// (which reads `AppMessage::StreamData` events from the app_registry).
///
/// # Outbound (duplex read → veil APP_DATA back to initiator)
/// Reads bytes from the inner duplex half and sends them as APP_DATA to
/// the initiating peer.
pub async fn run_server_bridge(
    inner_half: tokio::io::DuplexStream,
    mut data_rx: mpsc::Receiver<Vec<u8>>,
    initiator_peer_id: [u8; 32],
    stream_id: u32,
    broadcaster: Arc<dyn FrameBroadcaster>,
) {
    let (mut ir, mut iw) = tokio::io::split(inner_half);

    // Inbound: data from veil (via accept loop) → duplex write.
    let iw_task = tokio::spawn(async move {
        while let Some(data) = data_rx.recv().await {
            if iw.write_all(&data).await.is_err() {
                break;
            }
        }
    });

    // Outbound: duplex read → APP_DATA back to initiator.
    let mut buf = vec![0u8; 65536];
    loop {
        let n = match ir.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        if !send_app_data(
            broadcaster.as_ref(),
            &initiator_peer_id,
            stream_id,
            &buf[..n],
        ) {
            break;
        }
    }

    send_app_close(broadcaster.as_ref(), &initiator_peer_id, stream_id);
    iw_task.abort();
}

// ── Tests ─────────────────────────────────────────────────────────────────────
//
// the rich end-to-end tests that exercised SessionTxRegistry +
// the dispatcher reception path lived here historically; they couple to
// veilcore concretes (SessionTxRegistry channels, decoded-frame
// inspection) and have been ported as integration tests under
// `veilcore/tests/` so `veil-proxy` itself stays free of veilcore
// deps. The unit tests below use a tiny in-process FrameBroadcaster
// mock for trait-level coverage.

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex as StdMutex;
    use std::time::Duration;
    use veil_proto::HEADER_SIZE;
    use veil_proto::codec::decode_header;
    use veil_proto::family::{AppMsg, FrameFamily};

    /// In-process `FrameBroadcaster` that records every `send_to` call
    /// and exposes the recorded frames for assertion.
    #[derive(Default)]
    struct RecordingBroadcaster {
        frames: StdMutex<VecDeque<(u8, Vec<u8>)>>,
    }

    impl RecordingBroadcaster {
        fn drain(&self) -> Vec<(u8, Vec<u8>)> {
            self.frames
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .drain(..)
                .collect()
        }
    }

    impl FrameBroadcaster for RecordingBroadcaster {
        fn send_to(&self, _peer: &[u8; 32], priority: u8, bytes: Vec<u8>) -> bool {
            self.frames
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push_back((priority, bytes));
            true
        }
        fn send_to_all_with_priority(&self, _priority: u8, _bytes: Arc<[u8]>) {}
        fn active_node_ids(&self) -> Vec<[u8; 32]> {
            Vec::new()
        }
    }

    /// BridgeSlot enforces `MAX_PROXY_BRIDGES`.
    #[test]
    fn bridge_slot_caps_at_max() {
        let counter = Arc::new(AtomicUsize::new(0));
        let cap = veil_proto::budget::MAX_PROXY_BRIDGES;
        // Drive counter close to the cap. We cannot allocate the full
        // 256 slots in a unit test cheaply, so set the counter directly
        // to cap-1 and confirm one acquire succeeds, then the next fails.
        counter.store(cap - 1, Ordering::Release);
        let last = BridgeSlot::try_acquire(Arc::clone(&counter));
        assert!(last.is_some(), "the (cap)-th slot must acquire");
        assert_eq!(counter.load(Ordering::Acquire), cap, "counter at cap");
        let denied = BridgeSlot::try_acquire(Arc::clone(&counter));
        assert!(denied.is_none(), "(cap+1)-th acquire must fail");
        // Drop releases.
        drop(last);
        assert_eq!(
            counter.load(Ordering::Acquire),
            cap - 1,
            "drop must release the slot"
        );
        // After release a new acquire succeeds again.
        let after = BridgeSlot::try_acquire(Arc::clone(&counter));
        assert!(after.is_some(), "post-release acquire must succeed");
    }

    /// BridgeSlot acquire is concurrency-safe.
    /// Spawns N tasks that race to acquire; assert the total count equals
    /// MIN(spawned, cap_remaining) — never exceeds the cap.
    #[tokio::test]
    async fn bridge_slot_concurrent_acquires_respect_cap() {
        let counter = Arc::new(AtomicUsize::new(0));
        let cap = veil_proto::budget::MAX_PROXY_BRIDGES;
        // Pre-fill to cap-3 so 3 slots remain.
        counter.store(cap - 3, Ordering::Release);

        let mut tasks = Vec::new();
        for _ in 0..16usize {
            let counter_clone = Arc::clone(&counter);
            tasks.push(tokio::spawn(async move {
                BridgeSlot::try_acquire(counter_clone)
            }));
        }
        let mut results = Vec::with_capacity(tasks.len());
        for t in tasks {
            results.push(t.await.unwrap());
        }
        let won = results.iter().filter(|s| s.is_some()).count();
        assert_eq!(won, 3, "exactly 3 slots should be acquirable (cap left)");
        // Counter should be at cap.
        assert_eq!(counter.load(Ordering::Acquire), cap);
    }

    /// When `data_tx` is dropped (e.g. because the accept loop removed the entry
    /// after a full-channel `try_send` error), `run_server_bridge` must send
    /// APP_CLOSE back to the initiating peer before exiting.
    #[tokio::test]
    async fn server_bridge_sends_app_close_when_data_tx_dropped() {
        let initiator_id = [0x0Au8; 32];
        let stream_id = 42u32;

        let broadcaster: Arc<RecordingBroadcaster> = Arc::new(RecordingBroadcaster::default());
        let broadcaster_trait: Arc<dyn FrameBroadcaster> = broadcaster.clone();

        // Bounded data channel, cap 1 — simulate overflow by dropping sender immediately.
        let (data_tx, data_rx) = mpsc::channel::<Vec<u8>>(1);

        // Duplex inner pipe for the bridge.
        let (_client_half, server_half) = tokio::io::duplex(4096);

        // Spawn the bridge.
        let bridge = tokio::spawn(run_server_bridge(
            server_half,
            data_rx,
            initiator_id,
            stream_id,
            broadcaster_trait,
        ));

        // Simulate accept-loop dropping the sender (overflow case).
        // Also drop the client duplex half so the outbound ir.read returns EOF.
        drop(data_tx);
        drop(_client_half);

        // Bridge should exit promptly and send APP_CLOSE.
        tokio::time::timeout(Duration::from_millis(500), bridge)
            .await
            .expect("bridge did not exit in time")
            .expect("bridge task panicked");

        // Drain frames recorded by the broadcaster and find APP_CLOSE.
        let frames = broadcaster.drain();
        let found_close = frames.iter().any(|(_priority, bytes)| {
            let hdr = decode_header(&bytes[..HEADER_SIZE]).unwrap();
            hdr.family == FrameFamily::App as u8 && hdr.msg_type == AppMsg::AppClose as u16
        });
        assert!(
            found_close,
            "expected APP_CLOSE frame in broadcaster outbox"
        );
    }
}
