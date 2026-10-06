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

use crate::exit::{encode_proxy_header, encode_udp_associate_header};
use crate::socks5::{BiStream, ProxyConnector, ProxyDestination, ProxyTransport, Socks5Error};

// ── Type aliases ─────────────────────────────────────────────────────────────

/// Map: `(peer_id, stream_id) → receipt waiter` for locally-initiated veil
/// streams. Keyed by the SAME `(node_id, wire_stream_id)` pair as
/// [`VeilStreamRxMap`] so a receipt is always matched to the exact opener:
/// the shared `wire_stream_counter` is a `u32`, so without the peer in the
/// key a 2^32 wraparound (over a very long-lived process) could let a late
/// receipt resolve a different peer's still-pending waiter.
pub type PendingReceiptMap = Arc<Mutex<HashMap<([u8; 32], u32), oneshot::Sender<u8>>>>;

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

/// A cold DHT route/key lookup is initiated by the routed broadcaster's first
/// failed send. Retry APP_OPEN while that lookup converges instead of failing
/// SOCKS immediately merely because the exit is not a direct neighbour.
const OPEN_ROUTE_RETRY_ATTEMPTS: usize = 120;
const OPEN_ROUTE_RETRY_INTERVAL: Duration = Duration::from_millis(100);

const STREAM_WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// per-bridge duplex buffer size — pulled from
/// `veil_proto::budget::PROXY_DUPLEX_BUF_SIZE`. Was 256 KiB locally;
/// reduced to 64 KiB to bound aggregate memory at 256 × 64 KiB = 16 MiB
/// instead of 128 MiB on a fully-loaded relay. Matches wire frame
/// sizing — one APP_DATA chunk fits in the pipe with headroom.
const DUPLEX_BUF_SIZE: usize = veil_proto::budget::PROXY_DUPLEX_BUF_SIZE;

/// Exit-side DNS + TCP connect is bounded by 10 seconds. Give the encrypted
/// stream a little extra scheduling margin, but never report SOCKS success
/// before the exit confirms that its outbound socket actually exists.
const EXIT_READY_TIMEOUT: Duration = Duration::from_secs(15);

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
            .insert((exit_node_id, stream_id), receipt_tx);

        // Register the inbound data channel.
        let (data_tx, data_rx) =
            mpsc::channel::<Vec<u8>>(veil_proto::budget::PROXY_STREAM_CHANNEL_CAP);
        self.veil_stream_rx
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert((exit_node_id, stream_id), data_tx);

        // Remove BOTH registrations (audit cycle-9). Every error path below must
        // clean up `pending_receipts` AND `veil_stream_rx`: previously the
        // timeout / sender-dropped / rejected paths removed only
        // `veil_stream_rx` and leaked the `pending_receipts` entry. `stream_id`
        // is a monotonic counter (never reused), so each leak was permanent and
        // the map grew unbounded under repeated APP_OPEN timeouts. On success the
        // `pending_receipts` entry is consumed by the receipt handler instead.
        let cleanup_regs = || {
            self.pending_receipts
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&(exit_node_id, stream_id));
            self.veil_stream_rx
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&(exit_node_id, stream_id));
        };

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

        // Bound route discovery AND source backpressure by the original open
        // budget. All stream lifecycle frames use the same local source lane;
        // the wire header remains neutral INTERACTIVE.
        let sent = timeout(
            OPEN_ROUTE_RETRY_INTERVAL * OPEN_ROUTE_RETRY_ATTEMPTS as u32,
            async {
                for attempt in 0..OPEN_ROUTE_RETRY_ATTEMPTS {
                    if self
                        .broadcaster
                        .send_reliable_to(&exit_node_id, frame.clone())
                        .await
                    {
                        return true;
                    }
                    if attempt + 1 < OPEN_ROUTE_RETRY_ATTEMPTS {
                        tokio::time::sleep(OPEN_ROUTE_RETRY_INTERVAL).await;
                    }
                }
                false
            },
        )
        .await
        .unwrap_or(false);
        if !sent {
            cleanup_regs();
            return Err(Socks5Error::ConnectFailed(
                "no route to exit node".to_owned(),
            ));
        }

        // Wait for APP_RECEIPT_ACCEPTED from the exit node.
        let status = timeout(OPEN_RECEIPT_TIMEOUT, receipt_rx)
            .await
            .map_err(|_| {
                cleanup_regs();
                Socks5Error::ConnectFailed("APP_OPEN receipt timeout".to_owned())
            })?
            .map_err(|_| {
                cleanup_regs();
                Socks5Error::ConnectFailed("APP_OPEN receipt sender dropped".to_owned())
            })?;

        use veil_proto::app::receipt_status;
        if status != receipt_status::ACCEPTED {
            cleanup_regs();
            return Err(Socks5Error::ConnectFailed(format!(
                "APP_OPEN rejected (status=0x{status:04x})"
            )));
        }

        // Create the bidirectional pipe.
        let (mut user_half, inner_half) = tokio::io::duplex(DUPLEX_BUF_SIZE);

        // Send the proxy-connect header as the first outbound APP_DATA.
        let proxy_header = match destination.transport {
            ProxyTransport::Tcp => encode_proxy_header(&destination.host, destination.port),
            ProxyTransport::UdpAssociation => encode_udp_associate_header(),
        };

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

        // APP_OPEN acceptance only means the remote endpoint admitted the
        // stream. The exit still has to resolve the destination, enforce its
        // SSRF policy and connect the outbound TCP socket. Historically the
        // connector returned here immediately, so SOCKS5 replied SUCCESS too
        // early and the exit's 0x00 readiness byte leaked into application
        // payload. Consume that byte here and fail the SOCKS request if the
        // exit closes or times out before becoming ready.
        if let Err(error) = await_exit_ready(&mut user_half).await {
            cleanup_regs();
            return Err(error);
        }

        Ok(Box::new(VeilBiStream {
            inner: user_half,
            _slot: bridge_slot,
        }))
    }
}

async fn await_exit_ready<R>(stream: &mut R) -> Result<(), Socks5Error>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut status = [0u8; 1];
    timeout(EXIT_READY_TIMEOUT, stream.read_exact(&mut status))
        .await
        .map_err(|_| Socks5Error::ConnectFailed("exit connect timeout".to_owned()))?
        .map_err(|error| {
            Socks5Error::ConnectFailed(format!(
                "exit closed before connect acknowledgement: {error}"
            ))
        })?;
    if status[0] != 0x00 {
        return Err(Socks5Error::ConnectFailed(format!(
            "exit rejected destination (status=0x{:02x})",
            status[0]
        )));
    }
    Ok(())
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
    if initial_data.is_empty()
        || send_app_data(broadcaster.as_ref(), &peer_id, stream_id, &initial_data).await
    {
        let mut buf = vec![0u8; 65536];
        loop {
            let n = match ir.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if !send_app_data(broadcaster.as_ref(), &peer_id, stream_id, &buf[..n]).await {
                break;
            }
        }
    }

    // Clean up the inbound channel map entry.
    veil_stream_rx_map
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(&(peer_id, stream_id));

    // Send APP_CLOSE.
    send_app_close(broadcaster.as_ref(), &peer_id, stream_id).await;

    iw_task.abort();
    let _ = iw_task.await;
}

// ── Frame encoding helpers ────────────────────────────────────────────────────

/// Packetize one proxy byte-stream write with one overall admission deadline.
/// Partial failure stops here; callers close instead of replaying the prefix.
async fn send_app_data(
    broadcaster: &dyn FrameBroadcaster,
    peer_id: &[u8; 32],
    stream_id: u32,
    data: &[u8],
) -> bool {
    timeout(STREAM_WRITE_TIMEOUT, async {
        let mut offset = 0;
        loop {
            let end = data
                .len()
                .min(offset + veil_proto::budget::LOCAL_PROXY_STREAM_SEGMENT_DATA_BYTES);
            let body = AppDataPayload {
                app_id: EXIT_PROXY_APP_ID,
                endpoint_id: EXIT_PROXY_ENDPOINT_ID,
                seq: 0,
                data: data[offset..end].to_vec(),
            }
            .encode();
            let frame = app_frame(stream_id, AppMsg::AppData, &body);
            if !broadcaster.send_reliable_to(peer_id, frame).await {
                return false;
            }
            offset = end;
            if offset == data.len() {
                return true;
            }
        }
    })
    .await
    .unwrap_or(false)
}

/// Encode and send an APP_CLOSE frame.
async fn send_app_close(broadcaster: &dyn FrameBroadcaster, peer_id: &[u8; 32], stream_id: u32) {
    let payload = AppClosePayload {
        app_id: EXIT_PROXY_APP_ID,
        endpoint_id: EXIT_PROXY_ENDPOINT_ID,
        reason: close_reason::NORMAL,
    };
    let body = payload.encode();
    let frame = app_frame(stream_id, AppMsg::AppClose, &body);
    let _ = timeout(
        STREAM_WRITE_TIMEOUT,
        broadcaster.send_reliable_to(peer_id, frame),
    )
    .await;
}

fn app_frame(stream_id: u32, msg: AppMsg, body: &[u8]) -> Vec<u8> {
    let mut hdr = FrameHeader::new(FrameFamily::App as u8, msg as u16);
    hdr.body_len = body.len() as u32;
    hdr.stream_id = stream_id;
    hdr.set_priority(priority::INTERACTIVE);
    let mut frame = encode_header(&hdr).to_vec();
    frame.extend_from_slice(body);
    frame
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
        )
        .await
        {
            break;
        }
    }

    send_app_close(broadcaster.as_ref(), &initiator_peer_id, stream_id).await;
    iw_task.abort();
    let _ = iw_task.await;
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

    #[tokio::test]
    async fn exit_ready_ack_is_consumed_before_application_payload() {
        let (mut client, mut exit) = tokio::io::duplex(64);
        exit.write_all(&[0x00]).await.unwrap();
        exit.write_all(b"payload").await.unwrap();

        await_exit_ready(&mut client).await.unwrap();
        let mut payload = [0u8; 7];
        client.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"payload");
    }

    #[tokio::test]
    async fn exit_ready_rejection_never_becomes_socks_success() {
        let (mut client, mut exit) = tokio::io::duplex(8);
        exit.write_all(&[0x01]).await.unwrap();

        let error = await_exit_ready(&mut client).await.unwrap_err();
        assert!(error.to_string().contains("rejected destination"));
    }

    #[tokio::test]
    async fn exit_eof_before_ack_never_becomes_socks_success() {
        let (mut client, exit) = tokio::io::duplex(8);
        drop(exit);

        let error = await_exit_ready(&mut client).await.unwrap_err();
        assert!(error.to_string().contains("closed before connect"));
    }

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

    #[tokio::test]
    async fn connect_preserves_open_header_data_close_order_and_consumes_ready() {
        struct Exit {
            sent: mpsc::UnboundedSender<(u8, Vec<u8>)>,
        }
        impl FrameBroadcaster for Exit {
            fn send_to(&self, _: &[u8; 32], lane: u8, frame: Vec<u8>) -> bool {
                self.sent.send((lane, frame)).is_ok()
            }
            fn send_to_all_with_priority(&self, _: u8, _: Arc<[u8]>) {}
            fn active_node_ids(&self) -> Vec<[u8; 32]> {
                Vec::new()
            }
        }
        let pending: PendingReceiptMap = Arc::default();
        let rx: VeilStreamRxMap = Arc::default();
        let (sent, mut frames) = mpsc::unbounded_channel();
        let conn = VeilConnector::new(
            Arc::new(Exit { sent }),
            [0; 32],
            [1; 32],
            pending.clone(),
            rx.clone(),
            Arc::new(AtomicU32::new(0)),
        );
        let exit_task = tokio::spawn(async move {
            let mut types = Vec::new();
            let mut user_bytes = Vec::new();
            loop {
                let (lane, frame) = frames.recv().await.unwrap();
                let header = decode_header(&frame).unwrap();
                assert_eq!(lane, priority::BACKGROUND);
                assert_eq!(header.priority(), priority::INTERACTIVE);
                types.push(header.msg_type);
                let key = ([2; 32], header.stream_id);
                if header.msg_type == AppMsg::AppOpen as u16 {
                    pending
                        .lock()
                        .unwrap()
                        .remove(&key)
                        .unwrap()
                        .send(veil_proto::app::receipt_status::ACCEPTED)
                        .unwrap();
                } else if header.msg_type == AppMsg::AppData as u16 {
                    let data = AppDataPayload::decode(&frame[HEADER_SIZE..]).unwrap().data;
                    if types.len() == 2 {
                        assert_eq!(data, encode_proxy_header("example.com", 443));
                        let inbound = rx.lock().unwrap().get(&key).unwrap().clone();
                        inbound.send(b"\x00ready payload".to_vec()).await.unwrap();
                    } else {
                        user_bytes.extend(data);
                    }
                } else {
                    assert_eq!(header.msg_type, AppMsg::AppClose as u16);
                    assert!(!rx.lock().unwrap().contains_key(&key));
                    assert_eq!(user_bytes, b"user payload");
                    assert_eq!(
                        types,
                        vec![
                            AppMsg::AppOpen as u16,
                            AppMsg::AppData as u16,
                            AppMsg::AppData as u16,
                            AppMsg::AppClose as u16
                        ]
                    );
                    break;
                }
            }
        });
        timeout(Duration::from_secs(2), async {
            let stream = conn
                .connect(
                    [2; 32],
                    &crate::socks5::ProxyDestination::tcp("example.com", 443),
                )
                .await
                .unwrap();
            let (mut reader, mut writer) = stream.split();
            let mut ready_payload = [0; 13];
            reader.read_exact(&mut ready_payload).await.unwrap();
            assert_eq!(&ready_payload, b"ready payload");
            writer.write_all(b"user payload").await.unwrap();
            writer.shutdown().await.unwrap();
            exit_task.await.unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn proxy_write_segments_reassemble_and_do_not_expose_local_lane() {
        let sink = RecordingBroadcaster::default();
        let data: Vec<_> = (0..67_000).map(|i| (i % 251) as u8).collect();
        assert!(send_app_data(&sink, &[4; 32], 42, &data).await);
        let frames = sink.drain();
        assert!(frames.len() > 1);
        let mut decoded = Vec::new();
        for (lane, bytes) in frames {
            assert_eq!(lane, priority::BACKGROUND);
            let hdr = decode_header(&bytes).unwrap();
            assert_eq!(hdr.priority(), priority::INTERACTIVE);
            assert_eq!(hdr.stream_id, 42);
            assert_eq!(hdr.msg_type, AppMsg::AppData as u16);
            let payload = AppDataPayload::decode(&bytes[HEADER_SIZE..]).unwrap();
            assert_eq!(payload.app_id, EXIT_PROXY_APP_ID);
            assert_eq!(payload.endpoint_id, EXIT_PROXY_ENDPOINT_ID);
            assert_eq!(payload.seq, 0);
            assert!(
                payload.data.len() <= veil_proto::budget::LOCAL_PROXY_STREAM_SEGMENT_DATA_BYTES
            );
            decoded.extend(payload.data);
        }
        assert_eq!(decoded, data);
        assert!(send_app_data(&sink, &[4; 32], 42, &[]).await);
        let empty = sink.drain();
        assert_eq!(empty.len(), 1);
        assert!(
            AppDataPayload::decode(&empty[0].1[HEADER_SIZE..])
                .unwrap()
                .data
                .is_empty()
        );
    }

    #[tokio::test]
    async fn partial_proxy_write_stops_without_replaying_accepted_prefix() {
        struct FailSecond {
            attempts: StdMutex<Vec<Vec<u8>>>,
        }
        impl FrameBroadcaster for FailSecond {
            fn send_to(&self, _: &[u8; 32], lane: u8, data: Vec<u8>) -> bool {
                assert_eq!(lane, priority::BACKGROUND);
                let mut attempts = self.attempts.lock().unwrap();
                attempts.push(data);
                attempts.len() != 2
            }
            fn send_to_all_with_priority(&self, _: u8, _: Arc<[u8]>) {}
            fn active_node_ids(&self) -> Vec<[u8; 32]> {
                Vec::new()
            }
        }
        let sink = FailSecond {
            attempts: StdMutex::new(Vec::new()),
        };
        let data: Vec<_> = (0..8000).map(|i| (i % 251) as u8).collect();
        assert!(!send_app_data(&sink, &[4; 32], 42, &data).await);
        let attempts = sink.attempts.lock().unwrap();
        assert_eq!(attempts.len(), 2);
        for (index, frame) in attempts.iter().enumerate() {
            let payload = AppDataPayload::decode(&frame[HEADER_SIZE..]).unwrap();
            let begin = index * veil_proto::budget::LOCAL_PROXY_STREAM_SEGMENT_DATA_BYTES;
            assert_eq!(payload.data, data[begin..begin + payload.data.len()]);
        }
    }

    #[tokio::test]
    async fn failed_initial_proxy_header_closes_before_user_bytes() {
        struct FailHeader {
            frames: RecordingBroadcaster,
        }
        impl FrameBroadcaster for FailHeader {
            fn send_to(&self, peer: &[u8; 32], lane: u8, data: Vec<u8>) -> bool {
                let accepted = decode_header(&data).unwrap().msg_type == AppMsg::AppClose as u16;
                self.frames.send_to(peer, lane, data);
                accepted
            }
            fn send_to_all_with_priority(&self, _: u8, _: Arc<[u8]>) {}
            fn active_node_ids(&self) -> Vec<[u8; 32]> {
                Vec::new()
            }
        }
        let sink = Arc::new(FailHeader {
            frames: RecordingBroadcaster::default(),
        });
        let (mut client, inner) = tokio::io::duplex(256);
        client
            .write_all(b"must not follow failed header")
            .await
            .unwrap();
        let (tx, rx) = mpsc::channel(1);
        let map = Arc::new(Mutex::new(HashMap::from([(([4; 32], 42), tx)])));
        timeout(
            Duration::from_secs(1),
            run_client_bridge(
                inner,
                rx,
                [4; 32],
                42,
                [1; 32],
                sink.clone(),
                map.clone(),
                b"header".to_vec(),
            ),
        )
        .await
        .unwrap();
        assert!(map.lock().unwrap().is_empty());
        let frames = sink.frames.drain();
        assert_eq!(frames.len(), 2);
        assert_eq!(
            AppDataPayload::decode(&frames[0].1[HEADER_SIZE..])
                .unwrap()
                .data,
            b"header"
        );
        assert_eq!(
            decode_header(&frames[1].1).unwrap().msg_type,
            AppMsg::AppClose as u16
        );
        assert!(
            frames
                .iter()
                .all(|(lane, frame)| *lane == priority::BACKGROUND
                    && decode_header(frame).unwrap().priority() == priority::INTERACTIVE)
        );
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
    #[tokio::test]
    async fn connect_cleanup_removes_both_maps_on_send_failure() {
        // audit cycle-9: every connect error path must remove BOTH
        // pending_receipts and veil_stream_rx. Previously the timeout /
        // sender-dropped / rejected paths removed only veil_stream_rx and leaked
        // the pending_receipts entry; with stream_id monotonic that grew the map
        // unbounded. The !sent path exercises the shared cleanup_regs closure.
        struct FailingBroadcaster;
        impl FrameBroadcaster for FailingBroadcaster {
            fn send_to(&self, _peer: &[u8; 32], _priority: u8, _bytes: Vec<u8>) -> bool {
                false
            }
            fn send_to_all_with_priority(&self, _priority: u8, _bytes: Arc<[u8]>) {}
            fn active_node_ids(&self) -> Vec<[u8; 32]> {
                Vec::new()
            }
        }
        let pending: PendingReceiptMap = Arc::new(Mutex::new(std::collections::HashMap::new()));
        let rx: VeilStreamRxMap = Arc::new(Mutex::new(std::collections::HashMap::new()));
        let conn = VeilConnector::new(
            Arc::new(FailingBroadcaster),
            [0u8; 32],
            [1u8; 32],
            Arc::clone(&pending),
            Arc::clone(&rx),
            Arc::new(AtomicU32::new(0)),
        );
        let dest = crate::socks5::ProxyDestination::tcp("example.com", 443);
        let res = conn.connect([2u8; 32], &dest).await;
        assert!(res.is_err(), "send failure must error");
        assert!(
            pending.lock().unwrap_or_else(|p| p.into_inner()).is_empty(),
            "pending_receipts must be cleaned up (no leak)"
        );
        assert!(
            rx.lock().unwrap_or_else(|p| p.into_inner()).is_empty(),
            "veil_stream_rx must be cleaned up"
        );
    }
}
