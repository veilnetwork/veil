//! Core IPC connection management.

use std::path::Path;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Mutex, mpsc};

use veil_ipc::transport::{self, IpcReadHalf, IpcStream, IpcWriteHalf};
use veilcore::proto::{
    AppBindOkPayload, AppBindPayload, AppIpcHelloOkPayload, AppIpcHelloPayload, FrameFamily,
    FrameHeader, IPC_PROTOCOL_VERSION, LocalAppMsg, codec, ipc_bind_flags,
};

use crate::error::ClientError;
use crate::handle::AppHandle;

/// safe-default: hard upper-bound on RPC reply wait.
/// Each request method wraps the oneshot `rx.await` in
/// `tokio::time::timeout(DEFAULT_REQUEST_TIMEOUT...)`; expiry
/// surfaces as `ClientError::Protocol("timeout waiting for...")`
/// instead of a UI hang. 5 s is generous for local IPC; per-call
/// override is a future API addition if operators need it.
pub(crate) const DEFAULT_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Helper for the common `tokio::oneshot::Receiver<T>` await pattern
/// used by all RPC-shaped client methods. Folds three error cases
/// into a single `ClientError`:
/// * timeout → `Protocol("timeout waiting for {what}")`
/// * sender dropped → `ConnectionClosed`
/// * value received → `Ok(value)`
pub(crate) async fn await_rpc_reply<T>(
    rx: tokio::sync::oneshot::Receiver<T>,
    what: &str,
) -> Result<T, ClientError> {
    match tokio::time::timeout(DEFAULT_REQUEST_TIMEOUT, rx).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(_)) => Err(ClientError::ConnectionClosed),
        Err(_) => Err(ClientError::Protocol(format!("timeout waiting for {what}"))),
    }
}

/// Remove abandoned senders (receiver dropped) from a pending RPC queue.
///
/// Without this, a caller-side timeout leaves the `oneshot::Sender` in the
/// FIFO even after the receiver is gone. Eventually `len() >= MAX_PENDING_OPS`
/// and legitimate callers get spuriously rejected. Run at every queue.push_back
/// site before the cap check.
pub(crate) fn prune_closed<T>(
    queue: &mut std::collections::VecDeque<tokio::sync::oneshot::Sender<T>>,
) {
    queue.retain(|tx| !tx.is_closed());
}

/// Pop the next non-closed waiter from a pending FIFO. Dispatcher-side
/// counterpart to [`prune_closed`]: ensures a late reply lands on a
/// still-listening caller rather than being silently discarded into an
/// abandoned slot, leaving subsequent legitimate callers waiting on the
/// reply that already passed them by.
pub(crate) fn pop_next_open<T>(
    queue: &mut std::collections::VecDeque<tokio::sync::oneshot::Sender<T>>,
) -> Option<tokio::sync::oneshot::Sender<T>> {
    while let Some(tx) = queue.pop_front() {
        if !tx.is_closed() {
            return Some(tx);
        }
    }
    None
}

// audit cycle-6 (P3 review): the former `pop_next_open_stream` (skip-closed) and
// `prune_closed_stream` helpers were removed. Skipping/removing an abandoned
// stream-open slot mis-aligns FIFO reply matching: StreamOpen has no correlation
// id, so the daemon's in-order reply IS the match — a timed-out waiter's late
// reply must be consumed-and-discarded in its FIFO slot (see the StreamOpenOk/
// StreamOpenErr handlers), not skipped onto a different live waiter (which would
// connect that caller to the wrong destination).

/// Shared write half: pushes encoded frames to a dedicated writer task so
/// `AppSender::send` does not block on a per-socket mutex (Phase E25).
#[derive(Clone)]
pub(crate) struct SharedWriter {
    tx: mpsc::Sender<Vec<u8>>,
}

pub(crate) const FRAME_TX_CAPACITY: usize = 1024;

/// Number of uninit bytes a caller must reserve at the FRONT of a
/// `Vec<u8>` before calling [`AppSender::send_prepared`]. Equal to
/// `FrameHeader (24) + AppIpcSendPayload::FIXED_SIZE (108)`.  Exposed
/// here so the ogate TUN reader can request exactly this much headroom
/// and avoid copying the data into a fresh frame buffer downstream.
pub const APP_IPC_SEND_PREFIX_BYTES: usize = 24 + 108;

impl SharedWriter {
    pub(crate) fn new(tx: mpsc::Sender<Vec<u8>>) -> Self {
        Self { tx }
    }

    pub(crate) async fn write_frame(&self, msg_type: u16, body: &[u8]) -> Result<(), ClientError> {
        let frame = encode_frame(msg_type, body);
        self.tx
            .send(frame)
            .await
            .map_err(|_| ClientError::ConnectionClosed)
    }

    /// Zero-data-copy variant: caller supplies a `Vec<u8>` that already
    /// has [`APP_IPC_SEND_PREFIX_BYTES`] uninit bytes reserved at the
    /// FRONT, followed by the IP packet (or other datagram payload).
    /// This method fills the prefix region in-place with FrameHeader +
    /// AppIpcSendPayload fixed fields, then moves the whole `buf` to the
    /// writer task.  No memcpy of the payload bytes whatsoever.
    ///
    /// Used by ogate's solo-ship hot path where the TUN reader allocates
    /// the buffer with the prefix reserved (see. `Reader::read_packet_with_prefix`).
    pub(crate) async fn send_prepared_app_ipc_send(
        &self,
        mut buf: Vec<u8>,
        dst_node_id: &[u8; 32],
        src_app_id: &[u8; 32],
        dst_app_id: &[u8; 32],
        endpoint_id: u32,
        flags: u32,
    ) -> Result<(), ClientError> {
        use veil_proto::header::HEADER_SIZE;
        const FIXED_SIZE: usize = 32 + 32 + 32 + 4 + 4 + 4; // matches AppIpcSendPayload::FIXED_SIZE
        debug_assert!(
            buf.len() >= APP_IPC_SEND_PREFIX_BYTES,
            "send_prepared_app_ipc_send: buf shorter than reserved prefix",
        );
        let data_len = buf.len() - APP_IPC_SEND_PREFIX_BYTES;
        let body_len = FIXED_SIZE + data_len;

        // FrameHeader at [0..HEADER_SIZE].
        let mut hdr = FrameHeader::new(FrameFamily::LocalApp as u8, LocalAppMsg::AppIpcSend as u16);
        hdr.body_len = body_len as u32;
        buf[..HEADER_SIZE].copy_from_slice(&codec::encode_header(&hdr));

        // AppIpcSendPayload fixed fields at [HEADER_SIZE..APP_IPC_SEND_PREFIX_BYTES].
        let mut p = HEADER_SIZE;
        buf[p..p + 32].copy_from_slice(dst_node_id);
        p += 32;
        buf[p..p + 32].copy_from_slice(src_app_id);
        p += 32;
        buf[p..p + 32].copy_from_slice(dst_app_id);
        p += 32;
        buf[p..p + 4].copy_from_slice(&endpoint_id.to_be_bytes());
        p += 4;
        buf[p..p + 4].copy_from_slice(&flags.to_be_bytes());
        p += 4;
        buf[p..p + 4].copy_from_slice(&(data_len as u32).to_be_bytes());

        self.tx
            .send(buf)
            .await
            .map_err(|_| ClientError::ConnectionClosed)
    }

    /// Hot-path encoder for `APP_IPC_SEND` that builds the IPC frame
    /// (FrameHeader + AppIpcSendPayload fixed fields + data) in a
    /// single buffer, one allocation, one copy of `data`.
    ///
    /// Pre-patch the call chain was:
    /// 1. `AppIpcSendPayload::encode()` → fresh `Vec` of FIXED_SIZE +
    ///    data.len(); memcpy of data.
    /// 2. `SharedWriter::write_frame()` → `encode_frame()` builds
    ///    yet another fresh `Vec` of HEADER_SIZE + body.len(); ANOTHER
    ///    memcpy of the same data.
    ///
    /// On ogate egress hot path (16 K-sized IP packets) those two redundant
    /// memcopies showed up in local-bench profiles.  Single-buffer
    /// encode skips the second copy entirely.
    pub(crate) async fn write_app_ipc_send_owned(
        &self,
        dst_node_id: &[u8; 32],
        src_app_id: &[u8; 32],
        dst_app_id: &[u8; 32],
        endpoint_id: u32,
        flags: u32,
        data: &[u8],
    ) -> Result<(), ClientError> {
        use veil_proto::header::HEADER_SIZE;
        const FIXED_SIZE: usize = 32 + 32 + 32 + 4 + 4 + 4; // matches AppIpcSendPayload::FIXED_SIZE
        let body_len = FIXED_SIZE + data.len();
        let total = HEADER_SIZE + body_len;
        let mut frame = Vec::with_capacity(total);

        // FrameHeader.
        let mut hdr = FrameHeader::new(FrameFamily::LocalApp as u8, LocalAppMsg::AppIpcSend as u16);
        hdr.body_len = body_len as u32;
        frame.extend_from_slice(&codec::encode_header(&hdr));

        // AppIpcSendPayload fixed fields.
        frame.extend_from_slice(dst_node_id);
        frame.extend_from_slice(src_app_id);
        frame.extend_from_slice(dst_app_id);
        frame.extend_from_slice(&endpoint_id.to_be_bytes());
        frame.extend_from_slice(&flags.to_be_bytes());
        frame.extend_from_slice(&(data.len() as u32).to_be_bytes());

        // Data.
        frame.extend_from_slice(data);

        debug_assert_eq!(frame.len(), total, "single-buffer encode size mismatch");

        self.tx
            .send(frame)
            .await
            .map_err(|_| ClientError::ConnectionClosed)
    }

    /// Reply-channel-aware `APP_IPC_SEND` encoder: like
    /// [`Self::write_app_ipc_send_owned`] but also appends the two trailing
    /// reply fields (`reply_id`, `reply_endpoint_id`) the daemon reads after the
    /// data. Used by the expect-reply and is-reply send paths, which are not the
    /// ogate hot path, so the extra 12 trailing bytes are immaterial.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn write_app_ipc_send_reply_aware(
        &self,
        dst_node_id: &[u8; 32],
        src_app_id: &[u8; 32],
        dst_app_id: &[u8; 32],
        endpoint_id: u32,
        flags: u32,
        reply_id: u64,
        reply_endpoint_id: u32,
        data: &[u8],
    ) -> Result<(), ClientError> {
        use veil_proto::header::HEADER_SIZE;
        const FIXED_SIZE: usize = 32 + 32 + 32 + 4 + 4 + 4; // matches AppIpcSendPayload::FIXED_SIZE
        const TRAILER: usize = 8 + 4; // reply_id + reply_endpoint_id
        let body_len = FIXED_SIZE + data.len() + TRAILER;
        let total = HEADER_SIZE + body_len;
        let mut frame = Vec::with_capacity(total);

        let mut hdr = FrameHeader::new(FrameFamily::LocalApp as u8, LocalAppMsg::AppIpcSend as u16);
        hdr.body_len = body_len as u32;
        frame.extend_from_slice(&codec::encode_header(&hdr));

        // AppIpcSendPayload fixed fields.
        frame.extend_from_slice(dst_node_id);
        frame.extend_from_slice(src_app_id);
        frame.extend_from_slice(dst_app_id);
        frame.extend_from_slice(&endpoint_id.to_be_bytes());
        frame.extend_from_slice(&flags.to_be_bytes());
        frame.extend_from_slice(&(data.len() as u32).to_be_bytes());

        // Data, then the trailing reply fields.
        frame.extend_from_slice(data);
        frame.extend_from_slice(&reply_id.to_be_bytes());
        frame.extend_from_slice(&reply_endpoint_id.to_be_bytes());

        debug_assert_eq!(frame.len(), total, "reply-aware encode size mismatch");

        self.tx
            .send(frame)
            .await
            .map_err(|_| ClientError::ConnectionClosed)
    }

    /// A [`PollSender`](tokio_util::sync::PollSender) over a clone of the
    /// writer channel, for the `AsyncWrite::poll_*` paths.
    ///
    /// `PollSender::poll_reserve` registers the task waker with the bounded
    /// mpsc channel, so a writer blocked on a full channel is woken exactly
    /// once when capacity frees — replacing the previous `try_send` +
    /// `cx.waker().wake_by_ref()` busy-spin that re-polled continuously under
    /// backpressure.
    pub(crate) fn poll_sender(&self) -> tokio_util::sync::PollSender<Vec<u8>> {
        tokio_util::sync::PollSender::new(self.tx.clone())
    }
}

/// Encode a LocalApp-family frame (header + body) into a single buffer
/// ready to enqueue to the writer task.
pub(crate) fn encode_frame(msg_type: u16, body: &[u8]) -> Vec<u8> {
    let mut hdr = FrameHeader::new(FrameFamily::LocalApp as u8, msg_type);
    hdr.body_len = body.len() as u32;
    let header_bytes = codec::encode_header(&hdr);
    let mut frame = Vec::with_capacity(header_bytes.len() + body.len());
    frame.extend_from_slice(&header_bytes);
    frame.extend_from_slice(body);
    frame
}

pub(crate) async fn run_writer_task(mut wh: IpcWriteHalf, mut rx: mpsc::Receiver<Vec<u8>>) {
    /// Cap on frames drained in one batch — bounds the worst-case syscall
    /// size at writev-style concat and keeps tail-latency for interactive
    /// frames bounded.
    const DRAIN_CAP: usize = 16;

    while let Some(first) = rx.recv().await {
        // Drain any frames that are already sitting in the channel — pure
        // `try_recv` peek-ahead, no await between recv()s.  This avoids
        // a recv()→write→recv()→write ping-pong when the egress task is
        // bursty (e.g. ogate has just shipped multiple back-to-back batch
        // envelopes), turning N awaits into 1 + N − 1 cheap try_recv calls.
        let mut frames: Vec<Vec<u8>> = Vec::with_capacity(DRAIN_CAP);
        frames.push(first);
        while frames.len() < DRAIN_CAP {
            match rx.try_recv() {
                Ok(more) => frames.push(more),
                Err(_) => break,
            }
        }
        let mut failed = false;
        for f in frames {
            if wh.write_all(&f).await.is_err() {
                failed = true;
                break;
            }
        }
        if failed {
            break;
        }
    }
    let _ = wh.shutdown().await;
}

/// Connected client session with the local veil node.
///
/// Created by [`VeilClient::connect`]. The underlying Unix-domain socket
/// is split into a shared write half (used by all [`AppHandle`]s) and a read
/// half that is drained by an internal dispatcher task.
pub struct VeilClient {
    /// Shared write half — cloned by each `AppHandle`.
    pub(crate) writer: SharedWriter,
    /// Dispatch table: `endpoint_id` → message sender.
    pub(crate) dispatch: Arc<Mutex<DispatchTable>>,
    /// Authentication token returned by the node in the HELLO_OK response.
    pub client_token: [u8; 16],
    /// handle to the dispatch reader
    /// task, aborted on `VeilClient` drop so the task does not
    /// linger on a closed IPC socket holding (now-dropped)
    /// dispatch table. Without this, on `VeilClient::drop`, the
    /// reader stays alive until its blocking `read_frame_raw` returns
    /// an error from the OS — typically immediate, but in pathological
    /// cases (kernel-level buffering on a non-Linux host) the task
    /// could hold an `Arc<Mutex<DispatchTable>>` reference for an
    /// arbitrary window.
    reader_task: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for VeilClient {
    fn drop(&mut self) {
        if let Some(task) = self.reader_task.take() {
            task.abort();
        }
    }
}

/// Per-endpoint message dispatch table.
type PendingStreamOpen = (
    tokio::sync::oneshot::Sender<Result<u32, ClientError>>,
    mpsc::Sender<StreamEvent>,
);

pub(crate) struct DispatchTable {
    pub endpoints: std::collections::HashMap<u32, mpsc::Sender<crate::handle::IncomingMessage>>,
    pub streams: std::collections::HashMap<u32, mpsc::Sender<StreamEvent>>,
    /// Per-endpoint inbound-stream queues (Phase 6.51).  Keyed by
    /// `endpoint_id` — the IPC's `StreamOpenInboundPayload` carries both
    /// `app_id` AND `endpoint_id`, but we route on `endpoint_id` alone (cheap
    /// u32 lookup). Correctness relies on `endpoint_id` being unique per
    /// connection; `bind_with_flags` enforces that by rejecting a duplicate
    /// endpoint_id (audit L-19/L-20). `app_id` is NOT compared on the routing
    /// path. Removed in every endpoint-cleanup path alongside `endpoints`
    /// (audit L-18).
    pub inbound_streams:
        std::collections::HashMap<u32, mpsc::Sender<crate::handle::IncomingStream>>,
    pub pending_binds: std::collections::VecDeque<
        tokio::sync::oneshot::Sender<Result<veilcore::proto::AppBindOkPayload, ClientError>>,
    >,
    pub pending_stream_opens: std::collections::VecDeque<PendingStreamOpen>,
    /// pending oneshot replies for `GetNodeIdentity`.
    /// FIFO — apps making concurrent identity queries get matched in order.
    pub pending_node_identity:
        std::collections::VecDeque<tokio::sync::oneshot::Sender<NodeIdentity>>,
    /// pending oneshot replies for `GetPeers`.
    pub pending_peers_list:
        std::collections::VecDeque<tokio::sync::oneshot::Sender<Vec<PeerEntry>>>,
    /// S2.A: pending oneshot replies for `PnetStatusQuery`.
    pub pending_pnet_status: std::collections::VecDeque<tokio::sync::oneshot::Sender<PnetStatus>>,
    /// pending oneshot replies for `JoinBootstrapUri`.
    pub pending_bootstrap_join:
        std::collections::VecDeque<tokio::sync::oneshot::Sender<JoinBootstrapResult>>,
    /// pending oneshot replies for `CreateBootstrapInvite` (Epic 489.7
    /// generator side).
    pub pending_create_invite:
        std::collections::VecDeque<tokio::sync::oneshot::Sender<CreateBootstrapInviteReply>>,
    /// Epic 489.8 multi-device pairing — Source side replies.
    pub pending_pair_source_create:
        std::collections::VecDeque<tokio::sync::oneshot::Sender<PairCreateInviteReply>>,
    pub pending_pair_source_hello:
        std::collections::VecDeque<tokio::sync::oneshot::Sender<PairOobReply>>,
    pub pending_pair_source_confirm:
        std::collections::VecDeque<tokio::sync::oneshot::Sender<PairStatusReply>>,
    /// Epic 489.8 multi-device pairing — Target side replies.
    pub pending_pair_target_consume:
        std::collections::VecDeque<tokio::sync::oneshot::Sender<PairFrameReply>>,
    pub pending_pair_target_cert:
        std::collections::VecDeque<tokio::sync::oneshot::Sender<PairOobReply>>,
    pub pending_pair_target_confirm:
        std::collections::VecDeque<tokio::sync::oneshot::Sender<PairFrameReply>>,
    /// pending oneshot replies for `GetMobileStatus`.
    pub pending_mobile_status:
        std::collections::VecDeque<tokio::sync::oneshot::Sender<MobileStatus>>,
    ///.2: pending oneshot replies for `SetPushEnvelope`.
    pub pending_set_push_envelope: std::collections::VecDeque<
        tokio::sync::oneshot::Sender<veilcore::proto::SetPushEnvelopeStatus>,
    >,
    /// Epic 489.10 slice 4.3.4: pending oneshot replies for
    /// `SetWakeHmacEnvelope`.  Same dispatch pattern as the push
    /// envelope queue.
    pub pending_set_wake_hmac_envelope: std::collections::VecDeque<
        tokio::sync::oneshot::Sender<veilcore::proto::SetWakeHmacEnvelopeStatus>,
    >,
    /// Pending oneshot replies for `RegisterOnionService` (2-byte status; 0=ok).
    pub pending_register_onion_service:
        std::collections::VecDeque<tokio::sync::oneshot::Sender<u16>>,
    ///.4 P2: pending oneshot replies for `MailboxPut`.
    pub pending_mailbox_put:
        std::collections::VecDeque<tokio::sync::oneshot::Sender<MailboxPutReply>>,
    ///.4 P2: pending oneshot replies for `MailboxFetch`.
    pub pending_mailbox_fetch:
        std::collections::VecDeque<tokio::sync::oneshot::Sender<Vec<MailboxBlobInfo>>>,
    ///.4 P2: pending oneshot replies for `MailboxAck`.
    pub pending_mailbox_ack: std::collections::VecDeque<tokio::sync::oneshot::Sender<bool>>,
    ///.4 P4: pending oneshot replies for `OutboxPut`.
    pub pending_outbox_put: std::collections::VecDeque<tokio::sync::oneshot::Sender<bool>>,
    ///.4 P4: pending oneshot replies for `OutboxFindMissing`.
    pub pending_outbox_find_missing:
        std::collections::VecDeque<tokio::sync::oneshot::Sender<Vec<OutboxEntryInfo>>>,
    ///.4 P4: pending oneshot replies for `OutboxAck`.
    pub pending_outbox_ack: std::collections::VecDeque<tokio::sync::oneshot::Sender<bool>>,
    ///.4 P5c: pending oneshot replies for `LookupRendezvousReplicas`.
    pub pending_lookup_replicas:
        std::collections::VecDeque<tokio::sync::oneshot::Sender<Vec<RendezvousReplicaInfo>>>,
    /// push event sink. When set by [`VeilClient::events`]
    /// every incoming `LocalAppMsg::Event` is decoded and forwarded
    /// here. Single-subscriber by design — the Flutter UI fans the
    /// stream out itself if multiple widgets need it. Replaced (not
    /// merged) on a second `events` call so re-subscribing after a
    /// receiver drop just works.
    pub event_sink: Option<mpsc::Sender<VeilEvent>>,
}

/// Per-endpoint IncomingMessage queue depth. When full the dispatcher
/// drops new datagrams (matching the daemon's drop-on-overflow semantics
/// for session_outbox / tx_registry). Sized to absorb short bursts
/// while preventing unbounded memory growth when the application thread
/// can't keep up with delivery.
pub(crate) const ENDPOINT_QUEUE_CAP: usize = 256;

/// Cap on the per-stream `StreamEvent` queue (Data / Close events the
/// SDK forwards from the daemon to a bound `VeilStream`).
///
/// **Why bounded:** pre-fix this was `mpsc::unbounded_channel`, with the
/// rationale that the daemon's STREAM_DATA window cap (server-side
/// `route_data_from_a` checks `window_a_to_b`) would throttle A→B.
/// That argument breaks for the B→A direction (no window enforcement in
/// `route_data_from_b`) and for opener-requested huge initial windows
/// — a hostile or buggy peer could flood inbound STREAM_DATA frames
/// faster than the SDK consumer reads, pinning unbounded memory on
/// the budget-Android target the project optimises for.
///
/// 256 covers a full STREAM_INITIAL_WINDOW worth of small frames plus
/// substantial headroom; consumers that fall behind get a stream
/// closure (visible via `recv()` → None → EOF in `VeilStream`),
/// matching the server-side backpressure-close pattern shipped in
/// `route_data_from_a` / `route_data_from_b`.
pub(crate) const STREAM_EVENT_QUEUE_CAP: usize = 256;

/// Cap on the per-endpoint inbound-stream notification queue
/// (`IncomingStream` items emitted on `StreamOpenInbound` IPC frames).
///
/// **Why bounded:** matches the daemon-side `MAX_IPC_STREAMS_PER_CLIENT`
/// (256, see. `veil_proto::budget`).  Pre-fix the SDK queue was
/// unbounded, so a malicious peer firing the maximum allowed inbound
/// opens against a bound endpoint that did not call `accept_stream`
/// could allocate 256 `VeilStream` objects (each with its own
/// data-channel mpsc + writer Arc + state) — bounded RAM, but a
/// non-trivial wedge on cheap hardware.  At cap, additional inbound
/// notifications are dropped client-side; daemon's own cap takes over
/// then reject future opens.
pub(crate) const INBOUND_STREAM_QUEUE_CAP: usize = 256;

/// Events that can be routed to an active `VeilStream`.
pub(crate) enum StreamEvent {
    Data(Vec<u8>),
    Close,
}

/// Maximum pending bind/stream-open requests before new ones are rejected.
pub(crate) const MAX_PENDING_OPS: usize = 256;

/// audit cycle-6 (P3): hard cap on how long `open_stream` waits for the
/// daemon's `StreamOpenOk`/`StreamOpenErr` reply. A stream open may involve
/// remote routing / session setup, so this is more generous than
/// `DEFAULT_REQUEST_TIMEOUT` (matching `BIND_TIMEOUT_DEFAULT`'s philosophy).
/// Without it, a daemon that accepted the StreamOpen frame but never replies
/// (alive but wedged) left the caller awaiting forever.
pub(crate) const STREAM_OPEN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// followup: hard cap on how long [`VeilClient::bind`]
/// (and its named/flagged variants) waits for the daemon's
/// `AppBindOk` / `AppBindErr` reply before erroring out.
///
/// **Why bounded:** previously the bind await was unbounded — a bug in
/// the daemon (e.g. routing layer still initializing right after a
/// `systemctl restart veil`) could leave the client task wedged
/// forever with no observable error to systemd's watchdog. Reproduced
/// sporadically on testnet's node1 / node5 post-deploy:
/// banner printed (bind succeeded earlier) → first send hung > 6 min
/// → service shown as `active` indefinitely.
///
/// 30 s is comfortably longer than the daemon's typical readiness
/// window (~ a few hundred ms cold-start) and shorter than systemd's
/// default `WatchdogSec=` so a hard-failed bind triggers a normal
/// service restart cycle rather than systemd's last-resort kill-9.
pub(crate) const BIND_TIMEOUT_DEFAULT: std::time::Duration = std::time::Duration::from_secs(30);

impl DispatchTable {
    fn new() -> Self {
        Self {
            endpoints: Default::default(),
            streams: Default::default(),
            inbound_streams: Default::default(),
            pending_binds: std::collections::VecDeque::new(),
            pending_stream_opens: std::collections::VecDeque::new(),
            pending_node_identity: std::collections::VecDeque::new(),
            pending_peers_list: std::collections::VecDeque::new(),
            pending_pnet_status: std::collections::VecDeque::new(),
            pending_bootstrap_join: std::collections::VecDeque::new(),
            pending_create_invite: std::collections::VecDeque::new(),
            pending_pair_source_create: std::collections::VecDeque::new(),
            pending_pair_source_hello: std::collections::VecDeque::new(),
            pending_pair_source_confirm: std::collections::VecDeque::new(),
            pending_pair_target_consume: std::collections::VecDeque::new(),
            pending_pair_target_cert: std::collections::VecDeque::new(),
            pending_pair_target_confirm: std::collections::VecDeque::new(),
            pending_mobile_status: std::collections::VecDeque::new(),
            pending_set_push_envelope: std::collections::VecDeque::new(),
            pending_set_wake_hmac_envelope: std::collections::VecDeque::new(),
            pending_register_onion_service: std::collections::VecDeque::new(),
            pending_mailbox_put: std::collections::VecDeque::new(),
            pending_mailbox_fetch: std::collections::VecDeque::new(),
            pending_mailbox_ack: std::collections::VecDeque::new(),
            pending_outbox_put: std::collections::VecDeque::new(),
            pending_outbox_find_missing: std::collections::VecDeque::new(),
            pending_outbox_ack: std::collections::VecDeque::new(),
            pending_lookup_replicas: std::collections::VecDeque::new(),
            event_sink: None,
        }
    }
}

impl VeilClient {
    /// Connect to the veil node's IPC socket and perform the APP_HELLO
    /// handshake.
    ///
    /// # Backend discovery
    ///
    /// `socket_path` is treated as an *anchor*: if its parent directory
    /// contains `ipc.port` + `ipc.token` sidecars, the client connects via
    /// TCP-loopback with token authentication. Otherwise it falls back to
    /// the legacy Unix-socket flow (path is the actual socket file).
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Handshake`] if the node rejects the connection
    /// (e.g. protocol version mismatch or the node is shutting down).
    pub async fn connect(socket_path: impl AsRef<Path>) -> Result<Self, ClientError> {
        // hello-handshake timeout. Without this, a daemon
        // that accepted the connection but failed to register a Hello
        // handler (e.g. silent IPC server bind-failure path) leaves the
        // client read-blocked forever. 5 s is generous enough for any
        // legitimate slow start (cold daemon, page faults) while turning
        // a hung daemon into a clean diagnosable error.
        const HELLO_TIMEOUT_SECS: u64 = 5;
        let timeout = std::time::Duration::from_secs(HELLO_TIMEOUT_SECS);

        let mut stream = tokio::time::timeout(timeout, connect_ipc_any(socket_path.as_ref()))
            .await
            .map_err(|_| {
                ClientError::Protocol(format!(
                    "IPC connect timed out after {HELLO_TIMEOUT_SECS}s — daemon not listening?",
                ))
            })??;

        // ── Send APP_HELLO ────────────────────────────────────────────────
        let hello = AppIpcHelloPayload {
            version: IPC_PROTOCOL_VERSION,
            flags: 0,
        };
        tokio::time::timeout(
            timeout,
            write_frame_raw(
                &mut stream,
                FrameFamily::LocalApp as u8,
                LocalAppMsg::AppHello as u16,
                &hello.encode(),
            ),
        )
        .await
        .map_err(|_| {
            ClientError::Protocol(format!(
                "IPC AppHello write timed out after {HELLO_TIMEOUT_SECS}s",
            ))
        })??;

        // ── Read APP_HELLO_OK / APP_HELLO_ERR ────────────────────────────
        let (hdr, body) = tokio::time::timeout(timeout, read_frame_raw(&mut stream))
            .await
            .map_err(|_| {
                ClientError::Protocol(format!(
                    "IPC AppHelloOk read timed out after {HELLO_TIMEOUT_SECS}s — daemon \
                 accepted connection but did not respond; check daemon `ipc.run.exit_err` log",
                ))
            })??;
        if hdr.msg_type == LocalAppMsg::AppHelloErr as u16 {
            use veilcore::proto::AppIpcHelloErrPayload;
            let err = AppIpcHelloErrPayload::decode(&body)
                .map_err(|e| ClientError::Protocol(e.to_string()))?;
            return Err(ClientError::Handshake {
                code: err.error_code,
                detail: String::from_utf8_lossy(&err.detail).into_owned(),
            });
        }
        if hdr.msg_type != LocalAppMsg::AppHelloOk as u16 {
            return Err(ClientError::Protocol(format!(
                "expected APP_HELLO_OK, got msg_type={}",
                hdr.msg_type
            )));
        }
        let ok = AppIpcHelloOkPayload::decode(&body)
            .map_err(|e| ClientError::Protocol(e.to_string()))?;

        // ── Split socket ─────────────────────────────────────────────────
        let (rh, wh) = stream.into_split();
        let (frame_tx, frame_rx) = mpsc::channel::<Vec<u8>>(FRAME_TX_CAPACITY);
        tokio::spawn(run_writer_task(wh, frame_rx));
        let writer = SharedWriter::new(frame_tx);
        let dispatch = Arc::new(Mutex::new(DispatchTable::new()));

        // ── Spawn reader task ────────────────────────────────────────────
        // Pass the writer into reader_task so it can construct `VeilStream`s
        // on inbound-stream notifications (Phase 6.51).
        let dispatch_clone = Arc::clone(&dispatch);
        let writer_clone = writer.clone();
        let reader_task_handle = tokio::spawn(reader_task(rh, dispatch_clone, writer_clone));

        Ok(Self {
            writer,
            dispatch,
            client_token: ok.client_token,
            reader_task: Some(reader_task_handle),
        })
    }

    /// Bind a local application endpoint and return an [`AppHandle`].
    ///
    /// Bind an endpoint in **ephemeral** mode (default for most applications).
    ///
    /// The node mixes the per-connection `client_token` into `app_id` derivation
    /// so multiple processes using the same `(namespace, name, endpoint_id)` each
    /// receive a distinct address. The address is only valid for the lifetime of
    /// this connection; reconnecting produces a new `app_id`.
    ///
    /// Use [`bind_named`](Self::bind_named) for well-known services that need a
    /// stable, persistent address across restarts.
    pub async fn bind(
        &self,
        namespace: &str,
        name: &str,
        endpoint_id: u32,
    ) -> Result<AppHandle, ClientError> {
        self.bind_with_flags(namespace, name, endpoint_id, ipc_bind_flags::EPHEMERAL)
            .await
    }

    /// Bind an endpoint in **named** mode.
    ///
    /// `app_id = BLAKE3(node_id || namespace || name)` — deterministic and stable
    /// across reconnects. Only one client on a node can hold a given
    /// `(namespace, name, endpoint_id)` at a time; a second attempt returns
    /// `ClientError::Bind` with error code `ipc_bind_err::ALREADY_BOUND`.
    ///
    /// Use this for background services that expose a well-known address.
    /// For apps that may run as multiple instances, prefer [`bind`](Self::bind).
    pub async fn bind_named(
        &self,
        namespace: &str,
        name: &str,
        endpoint_id: u32,
    ) -> Result<AppHandle, ClientError> {
        self.bind_with_flags(namespace, name, endpoint_id, 0).await
    }

    async fn bind_with_flags(
        &self,
        namespace: &str,
        name: &str,
        endpoint_id: u32,
        flags: u16,
    ) -> Result<AppHandle, ClientError> {
        let bind = AppBindPayload {
            endpoint_id,
            flags,
            namespace: namespace.as_bytes().to_vec(),
            name: name.as_bytes().to_vec(),
        };

        // Register BOTH the endpoint channel AND the bind-response
        // oneshot BEFORE writing APP_BIND. A fast local-IPC daemon can
        // deliver APP_BIND_OK before the reader task could route it to
        // a not-yet-registered waiter, leaving the bind call to time
        // out. Single atomic critical section over both dispatch-table
        // mutations closes the race.
        let (tx, rx) = mpsc::channel(ENDPOINT_QUEUE_CAP);
        // Inbound-stream notification channel (Phase 6.51).  Bounded to
        // `INBOUND_STREAM_QUEUE_CAP` (= daemon's `MAX_IPC_STREAMS_PER_CLIENT`)
        // so a malicious peer firing the maximum-allowed inbound opens against
        // an endpoint that never `accept_stream`s does not pin unbounded SDK
        // memory.  Audit batch 2026-05-23.
        let (inbound_streams_tx, inbound_streams_rx) =
            mpsc::channel::<crate::handle::IncomingStream>(INBOUND_STREAM_QUEUE_CAP);
        use tokio::sync::oneshot;
        let (bind_tx, bind_rx) = oneshot::channel::<Result<AppBindOkPayload, ClientError>>();
        {
            let mut d = self.dispatch.lock().await;
            prune_closed(&mut d.pending_binds);
            if d.pending_binds.len() >= MAX_PENDING_OPS {
                return Err(ClientError::Protocol(
                    "too many pending bind requests".into(),
                ));
            }
            // Audit L-19: the dispatch tables route inbound AppDeliver /
            // StreamOpenInbound on `endpoint_id` alone, but the daemon keys
            // endpoints on (app_id, endpoint_id). Two binds on this connection
            // with the SAME endpoint_id (different app_ids) both succeed on the
            // daemon, but the second `insert` here would silently overwrite the
            // first's delivery channel → the first endpoint stops receiving with
            // no error. Reject the colliding bind loudly instead (endpoint_id
            // must be unique per connection — the SDK's local routing key).
            if d.endpoints.contains_key(&endpoint_id) {
                return Err(ClientError::Protocol(format!(
                    "endpoint_id {endpoint_id} is already bound on this connection"
                )));
            }
            d.endpoints.insert(endpoint_id, tx);
            // Per-endpoint inbound-stream queue keyed by endpoint_id
            // (matches StreamOpenInboundPayload routing fields).
            d.inbound_streams.insert(endpoint_id, inbound_streams_tx);
            d.pending_binds.push_back(bind_tx);
        }

        // Send APP_BIND. If the write fails, clean up both dispatch-table
        // entries we just registered — otherwise stale endpoint mapping +
        // dangling oneshot stay in the table.
        if let Err(e) = self
            .writer
            .write_frame(LocalAppMsg::AppBind as u16, &bind.encode())
            .await
        {
            let mut d = self.dispatch.lock().await;
            d.endpoints.remove(&endpoint_id);
            d.inbound_streams.remove(&endpoint_id); // audit L-18
            let _ = d.pending_binds.pop_back();
            return Err(e);
        }

        // Bound the bind await — an unbounded one wedges the client
        // task if the daemon never sends AppBindOk (e.g. routing layer
        // still initializing after a fresh `systemctl restart veil`).
        // Hard timeout surfaces this as a recoverable error so callers
        // can retry / rely on `systemd Restart=`.
        let result = match tokio::time::timeout(BIND_TIMEOUT_DEFAULT, bind_rx).await {
            Ok(Ok(Ok(ok))) => ok,
            Ok(Ok(Err(e))) => {
                // Clean up stale endpoint on protocol-level error.
                {
                    let mut d = self.dispatch.lock().await;
                    d.endpoints.remove(&endpoint_id);
                    d.inbound_streams.remove(&endpoint_id); // audit L-18
                }
                return Err(e);
            }
            Ok(Err(_recv)) => {
                // oneshot dropped — daemon close OR reader task exited.
                {
                    let mut d = self.dispatch.lock().await;
                    d.endpoints.remove(&endpoint_id);
                    d.inbound_streams.remove(&endpoint_id); // audit L-18
                }
                return Err(ClientError::ConnectionClosed);
            }
            Err(_elapsed) => {
                // Prune abandoned entries (this caller's `tx` is closed
                // because `rx` was dropped on timeout). The pop_front from
                // the legacy code popped a blind FIFO head, which could
                // remove the wrong tx if multiple binds raced; `prune_closed`
                // picks exactly the closed entries — i.e. ours + any other
                // abandoned ones. Dispatcher-side `pop_next_open` also
                // skips closed entries, so this is defence in depth.
                let mut d = self.dispatch.lock().await;
                prune_closed(&mut d.pending_binds);
                d.endpoints.remove(&endpoint_id);
                d.inbound_streams.remove(&endpoint_id); // audit L-18
                return Err(ClientError::Protocol(format!(
                    "bind timeout — daemon did not reply within {}s",
                    BIND_TIMEOUT_DEFAULT.as_secs(),
                )));
            }
        };

        Ok(AppHandle::new(
            result.app_id,
            result.endpoint_id,
            self.writer.clone(),
            Arc::clone(&self.dispatch),
            rx,
            inbound_streams_rx,
        ))
    }

    /// Tell the daemon what mobile-lifecycle tier this app is in.
    ///
    /// Daemon scales keepalive cadence so sessions survive OS-level Doze /
    /// iOS background-task suspension. Fire-and-forget: no reply frame.
    pub async fn set_mobile_background_mode(
        &self,
        mode: veilcore::proto::MobileBackgroundMode,
    ) -> Result<(), ClientError> {
        let payload = veilcore::proto::SetMobileBackgroundModePayload { mode };
        self.writer
            .write_frame(
                LocalAppMsg::SetMobileBackgroundMode as u16,
                &payload.encode(),
            )
            .await
    }

    /// Register a sealed FCM/APNs push-token envelope on a rendezvous-publisher
    /// entry. The envelope must be already
    /// sealed via `veil_anonymity::push_envelope::seal_push_envelope`
    /// before passing here — the daemon never sees the underlying token.
    /// Empty `envelope` clears the registration.
    ///
    /// Returns `SetPushEnvelopeStatus`: OK / NoMatchingRendezvous / EnvelopeTooLarge.
    pub async fn set_push_envelope(
        &self,
        rendezvous_node_id: [u8; 32],
        auth_cookie: [u8; 16],
        envelope: Vec<u8>,
    ) -> Result<veilcore::proto::SetPushEnvelopeStatus, ClientError> {
        if envelope.len() > veilcore::proto::MAX_PUSH_ENVELOPE_BYTES {
            return Ok(veilcore::proto::SetPushEnvelopeStatus::EnvelopeTooLarge);
        }
        let (tx, rx) = tokio::sync::oneshot::channel();
        {
            let mut d = self.dispatch.lock().await;
            prune_closed(&mut d.pending_set_push_envelope);
            if d.pending_set_push_envelope.len() >= MAX_PENDING_OPS {
                return Err(ClientError::Protocol(format!(
                    "set_push_envelope queue at cap ({MAX_PENDING_OPS}); daemon may be hung"
                )));
            }
            d.pending_set_push_envelope.push_back(tx);
        }
        let payload = veilcore::proto::SetPushEnvelopePayload {
            rendezvous_node_id,
            auth_cookie,
            envelope,
        };
        self.writer
            .write_frame(LocalAppMsg::SetPushEnvelope as u16, &payload.encode())
            .await?;
        match tokio::time::timeout(std::time::Duration::from_secs(5), rx).await {
            Ok(Ok(status)) => Ok(status),
            Ok(Err(_)) => Err(ClientError::Protocol("daemon dropped reply".into())),
            Err(_) => Err(ClientError::Protocol(
                "timeout waiting for SetPushEnvelopeOk".into(),
            )),
        }
    }

    /// Update the sealed wake-HMAC envelope on a rendezvous-publisher
    /// entry (Epic 489.10 slice 4.3.4 — analog to
    /// [`Self::set_push_envelope`]).  Empty `envelope` clears the
    /// registration (HMAC opt-out fallback).
    ///
    /// Returns `SetWakeHmacEnvelopeStatus`: OK / NoMatchingRendezvous /
    /// EnvelopeTooLarge.
    pub async fn set_wake_hmac_envelope(
        &self,
        rendezvous_node_id: [u8; 32],
        auth_cookie: [u8; 16],
        envelope: Vec<u8>,
    ) -> Result<veilcore::proto::SetWakeHmacEnvelopeStatus, ClientError> {
        if envelope.len() > veilcore::proto::MAX_WAKE_HMAC_ENVELOPE_BYTES {
            return Ok(veilcore::proto::SetWakeHmacEnvelopeStatus::EnvelopeTooLarge);
        }
        let (tx, rx) = tokio::sync::oneshot::channel();
        {
            let mut d = self.dispatch.lock().await;
            prune_closed(&mut d.pending_set_wake_hmac_envelope);
            if d.pending_set_wake_hmac_envelope.len() >= MAX_PENDING_OPS {
                return Err(ClientError::Protocol(format!(
                    "set_wake_hmac_envelope queue at cap ({MAX_PENDING_OPS}); daemon may be hung"
                )));
            }
            d.pending_set_wake_hmac_envelope.push_back(tx);
        }
        let payload = veilcore::proto::SetWakeHmacEnvelopePayload {
            rendezvous_node_id,
            auth_cookie,
            envelope,
        };
        self.writer
            .write_frame(LocalAppMsg::SetWakeHmacEnvelope as u16, &payload.encode())
            .await?;
        match tokio::time::timeout(std::time::Duration::from_secs(5), rx).await {
            Ok(Ok(status)) => Ok(status),
            Ok(Err(_)) => Err(ClientError::Protocol("daemon dropped reply".into())),
            Err(_) => Err(ClientError::Protocol(
                "timeout waiting for SetWakeHmacEnvelopeOk".into(),
            )),
        }
    }

    /// Register this node as a LOCATION-anonymous (onion) service: the daemon
    /// picks relays, builds an onion circuit to a rendezvous relay (so it never
    /// learns this node's location), and publishes the ad so clients can reach
    /// this node by its identity. `hop_count` is clamped to ≥ 2 by the daemon.
    /// `Ok(())` once the daemon accepts; a non-zero daemon status maps to an
    /// error (e.g. no relays available yet — retry later).
    pub async fn register_onion_service(&self, hop_count: u32) -> Result<(), ClientError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        {
            let mut d = self.dispatch.lock().await;
            prune_closed(&mut d.pending_register_onion_service);
            if d.pending_register_onion_service.len() >= MAX_PENDING_OPS {
                return Err(ClientError::Protocol(format!(
                    "register_onion_service queue at cap ({MAX_PENDING_OPS}); daemon may be hung"
                )));
            }
            d.pending_register_onion_service.push_back(tx);
        }
        let payload = veilcore::proto::RegisterOnionServicePayload { hop_count };
        self.writer
            .write_frame(LocalAppMsg::RegisterOnionService as u16, &payload.encode())
            .await?;
        match tokio::time::timeout(std::time::Duration::from_secs(10), rx).await {
            Ok(Ok(0)) => Ok(()),
            Ok(Ok(code)) => Err(ClientError::Protocol(format!(
                "register_onion_service rejected by daemon (status {code})"
            ))),
            Ok(Err(_)) => Err(ClientError::Protocol("daemon dropped reply".into())),
            Err(_) => Err(ClientError::Protocol(
                "timeout waiting for RegisterOnionServiceResult".into(),
            )),
        }
    }

    /// Deposit an encrypted blob in the daemon's mailbox for an offline
    /// receiver. No `auth_cookie`
    /// required — anyone can put; the per-receiver quota and rate
    /// limit at the mailbox layer gate this call.
    ///
    /// `push_envelope` (optional, P3) is the sealed FCM/APNs token
    /// the sender obtained from receiver's `RendezvousAd` in DHT.
    /// When supplied and storage returns `Stored`, the relay fires a
    /// wake-push to the receiver after this call returns. Pass
    /// `None` (or empty) when the receiver doesn't register push
    /// (e.g. desktop client — relay only stores).
    ///
    /// Returns the put outcome (Stored / Duplicate / quota / rate-
    /// limited / not-mailbox-relay). `evicted` is the count of older
    /// blobs the relay had to evict to fit (only nonzero on
    /// `Stored` when the global quota was the binding constraint).
    #[allow(clippy::too_many_arguments)]
    pub async fn mailbox_put(
        &self,
        receiver_id: [u8; 32],
        content_id: [u8; 32],
        sender_id: [u8; 32],
        blob: Vec<u8>,
        push_envelope: Option<Vec<u8>>,
        // optional receiver-signed mailbox
        // capability token, typically obtained from
        // [`Self::lookup_rendezvous_replicas`] which surfaces it on
        // [`veil_ipc::ResolvedReplica::capability_token`]. Pass
        // `None` for relays running with the default
        // `require_capability_token = false` (legacy permissive mode).
        capability_token: Option<Vec<u8>>,
        // Epic 489.10 slice 4.3.4 follow-up — sealed wake-HMAC envelope
        // copy-paste'd from the receiver's RendezvousAd `wake_hmac_envelope`
        // field.  Forwarded to the relay so it can mint a receiver-
        // verifiable HMAC tag when dispatching the wake push.  `None`
        // = sender did not propagate (legacy, or receiver did not
        // register for HMAC); relay falls back to unauthenticated wake.
        wake_hmac_envelope: Option<Vec<u8>>,
    ) -> Result<MailboxPutReply, ClientError> {
        if blob.len() > veilcore::proto::MAX_MAILBOX_BLOB_BYTES {
            return Ok(MailboxPutReply {
                status: veilcore::proto::MailboxPutStatus::QuotaGlobalExceeded,
                evicted: 0,
            });
        }
        let (tx, rx) = tokio::sync::oneshot::channel();
        {
            let mut d = self.dispatch.lock().await;
            prune_closed(&mut d.pending_mailbox_put);
            if d.pending_mailbox_put.len() >= MAX_PENDING_OPS {
                return Err(ClientError::Protocol(format!(
                    "mailbox_put queue at cap ({MAX_PENDING_OPS}); daemon may be hung"
                )));
            }
            d.pending_mailbox_put.push_back(tx);
        }
        let payload = veilcore::proto::MailboxPutPayload {
            receiver_id,
            content_id,
            sender_id,
            blob,
            push_envelope,
            capability_token,
            wake_hmac_envelope,
        };
        self.writer
            .write_frame(LocalAppMsg::MailboxPut as u16, &payload.encode())
            .await?;
        match tokio::time::timeout(std::time::Duration::from_secs(5), rx).await {
            Ok(Ok(reply)) => Ok(reply),
            Ok(Err(_)) => Err(ClientError::Protocol("daemon dropped reply".into())),
            Err(_) => Err(ClientError::Protocol(
                "timeout waiting for MailboxPutOk".into(),
            )),
        }
    }

    /// Fetch all blobs currently pending for `receiver_id`. `auth_cookie`
    /// must match one of the receiver's registered rendezvous-publisher
    /// entries; mismatch returns an empty list (cookie is not a probing
    /// oracle). Caller must call [`Self::mailbox_ack`] for each blob
    /// after end-to-end receipt confirmation.
    pub async fn mailbox_fetch(
        &self,
        receiver_id: [u8; 32],
        auth_cookie: [u8; 16],
    ) -> Result<Vec<MailboxBlobInfo>, ClientError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        {
            let mut d = self.dispatch.lock().await;
            prune_closed(&mut d.pending_mailbox_fetch);
            if d.pending_mailbox_fetch.len() >= MAX_PENDING_OPS {
                return Err(ClientError::Protocol(format!(
                    "mailbox_fetch queue at cap ({MAX_PENDING_OPS}); daemon may be hung"
                )));
            }
            d.pending_mailbox_fetch.push_back(tx);
        }
        let payload = veilcore::proto::MailboxFetchPayload {
            receiver_id,
            auth_cookie,
        };
        self.writer
            .write_frame(LocalAppMsg::MailboxFetch as u16, &payload.encode())
            .await?;
        match tokio::time::timeout(std::time::Duration::from_secs(5), rx).await {
            Ok(Ok(blobs)) => Ok(blobs),
            Ok(Err(_)) => Err(ClientError::Protocol("daemon dropped reply".into())),
            Err(_) => Err(ClientError::Protocol(
                "timeout waiting for MailboxFetchResp".into(),
            )),
        }
    }

    /// Acknowledge end-to-end receipt of a blob. Daemon deletes the
    /// blob and frees its quota slice. Idempotent — a repeat ack
    /// returns `false`. `auth_cookie` is verified the same way as
    /// [`Self::mailbox_fetch`].
    pub async fn mailbox_ack(
        &self,
        receiver_id: [u8; 32],
        content_id: [u8; 32],
        auth_cookie: [u8; 16],
    ) -> Result<bool, ClientError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        {
            let mut d = self.dispatch.lock().await;
            prune_closed(&mut d.pending_mailbox_ack);
            if d.pending_mailbox_ack.len() >= MAX_PENDING_OPS {
                return Err(ClientError::Protocol(format!(
                    "mailbox_ack queue at cap ({MAX_PENDING_OPS}); daemon may be hung"
                )));
            }
            d.pending_mailbox_ack.push_back(tx);
        }
        let payload = veilcore::proto::MailboxAckPayload {
            receiver_id,
            content_id,
            auth_cookie,
        };
        self.writer
            .write_frame(LocalAppMsg::MailboxAck as u16, &payload.encode())
            .await?;
        match tokio::time::timeout(std::time::Duration::from_secs(5), rx).await {
            Ok(Ok(removed)) => Ok(removed),
            Ok(Err(_)) => Err(ClientError::Protocol("daemon dropped reply".into())),
            Err(_) => Err(ClientError::Protocol(
                "timeout waiting for MailboxAckOk".into(),
            )),
        }
    }

    /// Record a freshly-sent message in the daemon's sender-side
    /// outbox for later peer-sync retransmission.
    /// Returns `true` if stored, `false` if no outbox configured.
    pub async fn outbox_put(
        &self,
        receiver_id: [u8; 32],
        content_id: [u8; 32],
        blob: Vec<u8>,
    ) -> Result<bool, ClientError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        {
            let mut d = self.dispatch.lock().await;
            prune_closed(&mut d.pending_outbox_put);
            if d.pending_outbox_put.len() >= MAX_PENDING_OPS {
                return Err(ClientError::Protocol(format!(
                    "outbox_put queue at cap ({MAX_PENDING_OPS}); daemon may be hung"
                )));
            }
            d.pending_outbox_put.push_back(tx);
        }
        let payload = veilcore::proto::OutboxPutPayload {
            receiver_id,
            content_id,
            blob,
        };
        self.writer
            .write_frame(LocalAppMsg::OutboxPut as u16, &payload.encode())
            .await?;
        match tokio::time::timeout(std::time::Duration::from_secs(5), rx).await {
            Ok(Ok(stored)) => Ok(stored),
            Ok(Err(_)) => Err(ClientError::Protocol("daemon dropped reply".into())),
            Err(_) => Err(ClientError::Protocol(
                "timeout waiting for OutboxPutOk".into(),
            )),
        }
    }

    /// Find pending outbox entries for `receiver_id` deposited
    /// at-or-after `since` and not present in `bloom_bytes` (encoded
    /// `BloomFilter`). Used when the receiver shipped its received-
    /// content_id Bloom in a peer-sync request: app feeds the bloom
    /// here, gets back the missing entries, and retransmits them
    /// directly.
    pub async fn outbox_find_missing(
        &self,
        receiver_id: [u8; 32],
        since: u64,
        bloom: Vec<u8>,
    ) -> Result<Vec<OutboxEntryInfo>, ClientError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        {
            let mut d = self.dispatch.lock().await;
            prune_closed(&mut d.pending_outbox_find_missing);
            if d.pending_outbox_find_missing.len() >= MAX_PENDING_OPS {
                return Err(ClientError::Protocol(format!(
                    "outbox_find_missing queue at cap ({MAX_PENDING_OPS}); daemon may be hung"
                )));
            }
            d.pending_outbox_find_missing.push_back(tx);
        }
        let payload = veilcore::proto::OutboxFindMissingPayload {
            receiver_id,
            since,
            bloom,
        };
        self.writer
            .write_frame(LocalAppMsg::OutboxFindMissing as u16, &payload.encode())
            .await?;
        match tokio::time::timeout(std::time::Duration::from_secs(5), rx).await {
            Ok(Ok(entries)) => Ok(entries),
            Ok(Err(_)) => Err(ClientError::Protocol("daemon dropped reply".into())),
            Err(_) => Err(ClientError::Protocol(
                "timeout waiting for OutboxFindMissingResp".into(),
            )),
        }
    }

    /// Drop an outbox entry after end-to-end direct ack from the
    /// receiver. Idempotent. Returns `true` if removed, `false` if
    /// not present.
    pub async fn outbox_ack(
        &self,
        receiver_id: [u8; 32],
        content_id: [u8; 32],
    ) -> Result<bool, ClientError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        {
            let mut d = self.dispatch.lock().await;
            prune_closed(&mut d.pending_outbox_ack);
            if d.pending_outbox_ack.len() >= MAX_PENDING_OPS {
                return Err(ClientError::Protocol(format!(
                    "outbox_ack queue at cap ({MAX_PENDING_OPS}); daemon may be hung"
                )));
            }
            d.pending_outbox_ack.push_back(tx);
        }
        let payload = veilcore::proto::OutboxAckPayload {
            receiver_id,
            content_id,
        };
        self.writer
            .write_frame(LocalAppMsg::OutboxAck as u16, &payload.encode())
            .await?;
        match tokio::time::timeout(std::time::Duration::from_secs(5), rx).await {
            Ok(Ok(removed)) => Ok(removed),
            Ok(Err(_)) => Err(ClientError::Protocol("daemon dropped reply".into())),
            Err(_) => Err(ClientError::Protocol(
                "timeout waiting for OutboxAckOk".into(),
            )),
        }
    }

    /// Look up candidate mailbox-relays for `receiver_id` (
    /// T1.4 P5c —). Daemon resolves receiver's
    /// RendezvousAd from local DHT cache, verifies signature +
    /// freshness, returns up to `max_replicas` candidates the sender
    /// can fan-out mailbox puts to.
    ///
    /// `max_replicas == 0` means "all up to the daemon's cap"
    /// (currently `MAX_RENDEZVOUS_REPLICAS = 8`, though single-key
    /// publication today returns at most 1).
    ///
    /// Empty `Vec` ≠ permanent error — DHT cache may not yet have
    /// the receiver's ad. Caller can retry after a direct-delivery
    /// probe (which populates cache as a side effect).
    pub async fn lookup_rendezvous_replicas(
        &self,
        receiver_id: [u8; 32],
        max_replicas: u8,
    ) -> Result<Vec<RendezvousReplicaInfo>, ClientError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        {
            let mut d = self.dispatch.lock().await;
            prune_closed(&mut d.pending_lookup_replicas);
            if d.pending_lookup_replicas.len() >= MAX_PENDING_OPS {
                return Err(ClientError::Protocol(format!(
                    "lookup_rendezvous_replicas queue at cap ({MAX_PENDING_OPS}); daemon may be hung"
                )));
            }
            d.pending_lookup_replicas.push_back(tx);
        }
        let payload = veilcore::proto::LookupRendezvousReplicasPayload {
            receiver_id,
            max_replicas,
        };
        self.writer
            .write_frame(
                LocalAppMsg::LookupRendezvousReplicas as u16,
                &payload.encode(),
            )
            .await?;
        match tokio::time::timeout(std::time::Duration::from_secs(5), rx).await {
            Ok(Ok(entries)) => Ok(entries),
            Ok(Err(_)) => Err(ClientError::Protocol("daemon dropped reply".into())),
            Err(_) => Err(ClientError::Protocol(
                "timeout waiting for LookupRendezvousReplicasResp".into(),
            )),
        }
    }

    /// Notify the daemon that the local network attachment changed.
    ///
    /// Daemon eagerly retries gateway connect attempts, so the user-facing
    /// reconnect-after-Wi-Fi-flip latency drops from keepalive-timeout
    /// (~30 s) to sub-second. Fire-and-forget: no reply frame.
    ///
    /// Pass `mtu_hint = 0` if unknown (the wire-level "use default" value).
    pub async fn notify_network_changed(
        &self,
        kind: veilcore::proto::NetworkKind,
        mtu_hint: u16,
    ) -> Result<(), ClientError> {
        let payload = veilcore::proto::NetworkChangedPayload { kind, mtu_hint };
        self.writer
            .write_frame(LocalAppMsg::NetworkChanged as u16, &payload.encode())
            .await
    }

    /// Query the daemon for its own identity.
    ///
    /// Returns the daemon's `node_id` (32 bytes, derived from its signing
    /// pubkey), the signature algorithm in use (wire byte), and the raw
    /// public-key bytes. Useful for Flutter / Swift / Kotlin UIs that
    /// need to show the user "you are: 0xABC…" without scraping the
    /// `VEIL_LOCAL_NODE_ID` env var.
    pub async fn node_identity(&self) -> Result<NodeIdentity, ClientError> {
        // Register a oneshot for the reply BEFORE sending the request — the
        // reader task may dispatch the reply before our `send_frame` future
        // even returns.
        let (tx, rx) = tokio::sync::oneshot::channel();
        {
            let mut d = self.dispatch.lock().await;
            // cap pending requests so a hung
            // daemon (no replies arriving) doesn't grow this queue
            // unboundedly and exhaust the host's heap.
            prune_closed(&mut d.pending_node_identity);
            if d.pending_node_identity.len() >= MAX_PENDING_OPS {
                return Err(ClientError::Protocol(format!(
                    "node_identity queue at cap ({MAX_PENDING_OPS}); daemon may be hung"
                )));
            }
            d.pending_node_identity.push_back(tx);
        }

        // Send the empty-body request.
        self.writer
            .write_frame(LocalAppMsg::GetNodeIdentity as u16, &[])
            .await?;

        // Wait for the reader task to deliver the reply (bounded;
        // see DEFAULT_REQUEST_TIMEOUT for rationale).
        await_rpc_reply(rx, "node_identity reply").await
    }

    /// Snapshot the daemon's currently-active peer sessions.
    ///
    /// Returns a list of peers with their `node_id`, transport URI
    /// state (active / connecting / closed), and direction (inbound /
    /// outbound). Hard-capped at
    /// `veilcore::proto::MAX_PEERS_LIST_ENTRIES = 256` — daemons
    /// running heavily-loaded relays trim before encoding.
    ///
    /// Useful for Flutter UI that displays a "connected to N peers"
    /// indicator or peer-debug screen, without admin-token round-trip.
    pub async fn peers(&self) -> Result<Vec<PeerEntry>, ClientError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        {
            let mut d = self.dispatch.lock().await;
            // cap pending requests against a
            // hung daemon (see `node_identity` for the same guard).
            prune_closed(&mut d.pending_peers_list);
            if d.pending_peers_list.len() >= MAX_PENDING_OPS {
                return Err(ClientError::Protocol(format!(
                    "peers queue at cap ({MAX_PENDING_OPS}); daemon may be hung"
                )));
            }
            d.pending_peers_list.push_back(tx);
        }
        self.writer
            .write_frame(LocalAppMsg::GetPeers as u16, &[])
            .await?;
        await_rpc_reply(rx, "peers reply").await
    }

    /// Query the daemon's P-Net admission status for a peer.
    ///
    /// Returns a snapshot of: whether the daemon has an active session
    /// to the peer (`admitted`) and whether a valid `MembershipCert` was
    /// presented at handshake-time (`has_cert`).  Apps in strict-p_net
    /// admission mode reject when either flag is false.
    ///
    /// Example:
    /// ```ignore
    /// let status = client.peer_pnet_status(&peer_node_id).await?;
    /// if status.admitted && status.has_cert {
    ///     // peer admitted into the private network — accept their stream
    /// } else {
    ///     // reject — daemon hasn't verified a cert for this peer
    /// }
    /// ```
    pub async fn peer_pnet_status(
        &self,
        peer_node_id: &[u8; 32],
    ) -> Result<PnetStatus, ClientError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        {
            let mut d = self.dispatch.lock().await;
            prune_closed(&mut d.pending_pnet_status);
            if d.pending_pnet_status.len() >= MAX_PENDING_OPS {
                return Err(ClientError::Protocol(format!(
                    "pnet_status queue at cap ({MAX_PENDING_OPS}); daemon may be hung"
                )));
            }
            d.pending_pnet_status.push_back(tx);
        }
        self.writer
            .write_frame(LocalAppMsg::PnetStatusQuery as u16, peer_node_id)
            .await?;
        await_rpc_reply(rx, "pnet_status reply").await
    }

    /// Snapshot the daemon's current mobile/battery state.
    ///
    /// Returns the current background tier (Foreground/Active/LowPower)
    /// battery percentage (0-100; 100 = AC or unknown), configured
    /// keepalive + low-battery multipliers, and the EFFECTIVE factors
    /// being applied right now. Useful for Flutter UI that displays
    /// "Power-saving mode active" badges or helps the user diagnose
    /// "why is my keepalive 30 min?" without operator-level admin access.
    pub async fn mobile_status(&self) -> Result<MobileStatus, ClientError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        {
            let mut d = self.dispatch.lock().await;
            // cap pending requests against a
            // hung daemon (see `node_identity` for the same guard).
            prune_closed(&mut d.pending_mobile_status);
            if d.pending_mobile_status.len() >= MAX_PENDING_OPS {
                return Err(ClientError::Protocol(format!(
                    "mobile_status queue at cap ({MAX_PENDING_OPS}); daemon may be hung"
                )));
            }
            d.pending_mobile_status.push_back(tx);
        }
        self.writer
            .write_frame(LocalAppMsg::GetMobileStatus as u16, &[])
            .await?;
        await_rpc_reply(rx, "mobile_status reply").await
    }

    /// Decode a bootstrap-invite URI and register the resulting peer for
    /// outbound dial. The daemon owns the decode +
    /// verification pipeline (plain / encrypted / signed-invite); the
    /// app only forwards bytes. Closes the deep-link onboarding gap
    /// for Flutter / Swift / Kotlin apps that previously had to either
    /// re-implement decode in the host language or shell out to
    /// `veil-cli bootstrap join` (impossible from sandboxed mobile).
    ///
    /// `password` is required for `veil:pair?…` (encrypted) URIs
    /// and rejected for plain / signed. `expected_issuer_pk` is required
    /// for `veil:signed-invite?…` URIs (the signature is only useful
    /// when verified against an OOB-known pubkey) and rejected for plain /
    /// encrypted.
    pub async fn join_bootstrap_uri(
        &self,
        uri: &str,
        password: Option<&str>,
        expected_issuer_pk: Option<&str>,
    ) -> Result<JoinBootstrapResult, ClientError> {
        let payload = veilcore::proto::JoinBootstrapPayload {
            uri: uri.to_string(),
            password: password.map(String::from),
            expected_issuer_pk: expected_issuer_pk.map(String::from),
        };
        let (tx, rx) = tokio::sync::oneshot::channel();
        {
            let mut d = self.dispatch.lock().await;
            // cap pending requests against a
            // hung daemon (see `node_identity` for the same guard).
            prune_closed(&mut d.pending_bootstrap_join);
            if d.pending_bootstrap_join.len() >= MAX_PENDING_OPS {
                return Err(ClientError::Protocol(format!(
                    "join_bootstrap queue at cap ({MAX_PENDING_OPS}); daemon may be hung"
                )));
            }
            d.pending_bootstrap_join.push_back(tx);
        }
        self.writer
            .write_frame(LocalAppMsg::JoinBootstrapUri as u16, &payload.encode())
            .await?;
        await_rpc_reply(rx, "join_bootstrap_uri reply").await
    }

    /// Ask the daemon to assemble a bootstrap-invite URI from its own
    /// `[identity]` + first `[[listen]]` advertise (Epic 489.7 generator
    /// side).  Returns the canonical URI on success; structured error
    /// codes on missing config / bad password / daemon internal failure.
    ///
    /// `password = Some(pw)` emits an encrypted `veil:pair?…` envelope
    /// — receiver must supply the same passphrase on consume.  Empty
    /// password is rejected with `BadPassword` so the UI can re-prompt
    /// rather than emitting an envelope encrypted under a trivial key.
    pub async fn create_bootstrap_invite(
        &self,
        password: Option<&str>,
    ) -> Result<CreateBootstrapInviteReply, ClientError> {
        let payload = veilcore::proto::CreateBootstrapInvitePayload {
            password: password.map(String::from),
        };
        let (tx, rx) = tokio::sync::oneshot::channel();
        {
            let mut d = self.dispatch.lock().await;
            prune_closed(&mut d.pending_create_invite);
            if d.pending_create_invite.len() >= MAX_PENDING_OPS {
                return Err(ClientError::Protocol(format!(
                    "create_invite queue at cap ({MAX_PENDING_OPS}); daemon may be hung"
                )));
            }
            d.pending_create_invite.push_back(tx);
        }
        self.writer
            .write_frame(LocalAppMsg::CreateBootstrapInvite as u16, &payload.encode())
            .await?;
        await_rpc_reply(rx, "create_bootstrap_invite reply").await
    }

    // ── Multi-device pairing (Epic 489.8) ─────────────────────────────

    /// Source-side: generate a pair-invite URI + initialize ceremony.
    /// Daemon stashes state, returns URI to QR-render.
    pub async fn pair_source_create_invite(
        &self,
        master_password: Option<&str>,
    ) -> Result<PairCreateInviteReply, ClientError> {
        let payload = veilcore::proto::PairSourceCreateInvitePayload {
            master_password: master_password.map(String::from),
        };
        let (tx, rx) = tokio::sync::oneshot::channel();
        {
            let mut d = self.dispatch.lock().await;
            prune_closed(&mut d.pending_pair_source_create);
            if d.pending_pair_source_create.len() >= MAX_PENDING_OPS {
                return Err(ClientError::Protocol(format!(
                    "pair_source_create queue at cap ({MAX_PENDING_OPS})"
                )));
            }
            d.pending_pair_source_create.push_back(tx);
        }
        self.writer
            .write_frame(
                LocalAppMsg::PairSourceCreateInvite as u16,
                &payload.encode(),
            )
            .await?;
        await_rpc_reply(rx, "pair_source_create_invite reply").await
    }

    /// Source-side: process Hello bytes from Target, returns Cert +
    /// 6-digit OOB code.
    pub async fn pair_source_handle_hello(
        &self,
        hello_bytes: Vec<u8>,
    ) -> Result<PairOobReply, ClientError> {
        let payload = veilcore::proto::PairCeremonyFramePayload { bytes: hello_bytes };
        let (tx, rx) = tokio::sync::oneshot::channel();
        {
            let mut d = self.dispatch.lock().await;
            prune_closed(&mut d.pending_pair_source_hello);
            if d.pending_pair_source_hello.len() >= MAX_PENDING_OPS {
                return Err(ClientError::Protocol(format!(
                    "pair_source_hello queue at cap ({MAX_PENDING_OPS})"
                )));
            }
            d.pending_pair_source_hello.push_back(tx);
        }
        self.writer
            .write_frame(LocalAppMsg::PairSourceHandleHello as u16, &payload.encode())
            .await?;
        await_rpc_reply(rx, "pair_source_handle_hello reply").await
    }

    /// Source-side: process Confirm bytes — finalizes the ceremony,
    /// persists the new IdentityDocument with appended IdentityKey.
    pub async fn pair_source_handle_confirm(
        &self,
        confirm_bytes: Vec<u8>,
    ) -> Result<PairStatusReply, ClientError> {
        let payload = veilcore::proto::PairCeremonyFramePayload {
            bytes: confirm_bytes,
        };
        let (tx, rx) = tokio::sync::oneshot::channel();
        {
            let mut d = self.dispatch.lock().await;
            prune_closed(&mut d.pending_pair_source_confirm);
            if d.pending_pair_source_confirm.len() >= MAX_PENDING_OPS {
                return Err(ClientError::Protocol(format!(
                    "pair_source_confirm queue at cap ({MAX_PENDING_OPS})"
                )));
            }
            d.pending_pair_source_confirm.push_back(tx);
        }
        self.writer
            .write_frame(
                LocalAppMsg::PairSourceHandleConfirm as u16,
                &payload.encode(),
            )
            .await?;
        await_rpc_reply(rx, "pair_source_handle_confirm reply").await
    }

    /// Target-side: consume scanned URI, generate Hello bytes.
    pub async fn pair_target_consume_uri(&self, uri: &str) -> Result<PairFrameReply, ClientError> {
        self.pair_target_consume_uri_labeled(uri, None).await
    }

    /// Target-side consume with an optional human display label for the
    /// newly-paired device (Phase 4); `None` falls back to the daemon default.
    pub async fn pair_target_consume_uri_labeled(
        &self,
        uri: &str,
        instance_label: Option<&str>,
    ) -> Result<PairFrameReply, ClientError> {
        let payload = veilcore::proto::PairTargetConsumeUriPayload {
            uri: uri.to_string(),
            instance_label: instance_label.map(|s| s.to_string()),
        };
        let (tx, rx) = tokio::sync::oneshot::channel();
        {
            let mut d = self.dispatch.lock().await;
            prune_closed(&mut d.pending_pair_target_consume);
            if d.pending_pair_target_consume.len() >= MAX_PENDING_OPS {
                return Err(ClientError::Protocol(format!(
                    "pair_target_consume queue at cap ({MAX_PENDING_OPS})"
                )));
            }
            d.pending_pair_target_consume.push_back(tx);
        }
        self.writer
            .write_frame(LocalAppMsg::PairTargetConsumeUri as u16, &payload.encode())
            .await?;
        await_rpc_reply(rx, "pair_target_consume_uri reply").await
    }

    /// Target-side: process Cert bytes, returns 6-digit OOB code.
    pub async fn pair_target_handle_cert(
        &self,
        cert_bytes: Vec<u8>,
    ) -> Result<PairOobReply, ClientError> {
        let payload = veilcore::proto::PairCeremonyFramePayload { bytes: cert_bytes };
        let (tx, rx) = tokio::sync::oneshot::channel();
        {
            let mut d = self.dispatch.lock().await;
            prune_closed(&mut d.pending_pair_target_cert);
            if d.pending_pair_target_cert.len() >= MAX_PENDING_OPS {
                return Err(ClientError::Protocol(format!(
                    "pair_target_cert queue at cap ({MAX_PENDING_OPS})"
                )));
            }
            d.pending_pair_target_cert.push_back(tx);
        }
        self.writer
            .write_frame(LocalAppMsg::PairTargetHandleCert as u16, &payload.encode())
            .await?;
        await_rpc_reply(rx, "pair_target_handle_cert reply").await
    }

    /// Target-side: emit Confirm bytes based on user's OOB-compare
    /// decision.  `confirmed = true` also persists the new identity
    /// document to disk.
    pub async fn pair_target_build_confirm(
        &self,
        confirmed: bool,
    ) -> Result<PairFrameReply, ClientError> {
        let payload = veilcore::proto::PairTargetBuildConfirmPayload { confirmed };
        let (tx, rx) = tokio::sync::oneshot::channel();
        {
            let mut d = self.dispatch.lock().await;
            prune_closed(&mut d.pending_pair_target_confirm);
            if d.pending_pair_target_confirm.len() >= MAX_PENDING_OPS {
                return Err(ClientError::Protocol(format!(
                    "pair_target_confirm queue at cap ({MAX_PENDING_OPS})"
                )));
            }
            d.pending_pair_target_confirm.push_back(tx);
        }
        self.writer
            .write_frame(
                LocalAppMsg::PairTargetBuildConfirm as u16,
                &payload.encode(),
            )
            .await?;
        await_rpc_reply(rx, "pair_target_build_confirm reply").await
    }

    /// Subscribe to the daemon's push event stream.
    ///
    /// Returns a bounded receiver (capacity 1024 — see "Bounded" note
    /// below) that yields one [`VeilEvent`]
    /// per `LocalAppMsg::Event` frame the daemon emits over this IPC
    /// connection. Used by Flutter / native UIs to drive reactive
    /// state updates without polling — matters on budget Android where
    /// every wakeup costs battery.
    ///
    /// Single-subscriber semantics: calling `events` a second time
    /// replaces the previous sink. Drop the receiver to stop receiving
    /// events; the daemon keeps publishing on the bus regardless of
    /// subscribers.
    ///
    /// Bounded to 1024 events: events are tiny (≤ 4 KiB each) and rare
    /// (state transitions, not data flow), so 1024 is a generous buffer
    /// for transient consumer stalls — but bounded prevents unbounded
    /// memory growth if the consumer hangs entirely.
    ///
    /// Dispatcher uses `try_send` (see `dispatcher_loop` event handler);
    /// on a full channel the event is dropped and the sender is cleared
    /// to avoid log spam. Apps reading events should keep up with the
    /// daemon's event rate — they ARE the consumer.
    pub async fn events(&self) -> mpsc::Receiver<VeilEvent> {
        let (tx, rx) = mpsc::channel(1024);
        let mut d = self.dispatch.lock().await;
        d.event_sink = Some(tx);
        rx
    }
}

/// One push event delivered by the daemon over the IPC stream
///. Mirrors [`veil_proto::EventPayload`] but lives
/// in the SDK so consumers don't need a direct dep on the wire crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VeilEvent {
    /// Event kind byte — see `veil_proto::event_kind` constants.
    /// Unknown kinds are still delivered (forward-compat); apps should
    /// treat unrecognised kinds as a no-op rather than crashing.
    pub kind: u8,
    /// Per-kind opaque bytes. Layout depends on `kind` (see
    /// `veil_proto::event_kind` module docs for known shapes).
    pub payload: Vec<u8>,
}

/// Snapshot returned by [`VeilClient::mobile_status`] — UI-friendly
/// wrapper over `veil_proto::MobileStatusPayload`. All fields are
/// scalar wire bytes; apps interpret the sentinels themselves
/// (`battery_level_pct == 100` could mean "literal 100%" or "AC / unknown"
/// see proto module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MobileStatus {
    /// Current background tier: 0=Foreground / 1=Active / 2=LowPower.
    pub background_tier: u8,
    /// Configured `mobile.background_keepalive_multiplier`.
    pub background_keepalive_multiplier: u32,
    /// Effective background-keepalive factor RIGHT NOW.
    pub background_keepalive_factor: u32,
    /// Battery reading 0-100 (100 = AC / unknown).
    pub battery_level_pct: u8,
    /// Configured threshold for route-probe throttling (255 = disabled).
    pub low_battery_threshold_pct: u8,
    /// Configured route-probe multiplier on low-battery.
    pub low_battery_multiplier: u32,
    /// Effective route-probe factor RIGHT NOW.
    pub battery_route_probe_factor: u32,
}

/// Result [`VeilClient::join_bootstrap_uri`] — UI-friendly wrapper
/// over `veil_proto::JoinBootstrapResultPayload`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinBootstrapResult {
    /// Wire-byte status — see `veil_proto::join_status` constants
    /// (OK / ALREADY_REGISTERED / INVALID_URI / PASSWORD_REQUIRED /
    /// PASSWORD_WRONG / SIGNATURE_INVALID / INTERNAL_ERROR).
    pub status: u8,
    /// Decoded peer's `node_id` on success / ALREADY_REGISTERED;
    /// zero-filled otherwise.
    pub peer_node_id: [u8; 32],
    /// Human-readable detail (best-effort UTF-8; lossy on the SDK side
    /// for forward-compat with future status codes that ship non-UTF-8
    /// debug data).
    pub detail: String,
}

/// Reply [`VeilClient::pair_source_create_invite`] (Epic 489.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairCreateInviteReply {
    /// Wire-byte status — see `veil_proto::pair_source_status`.
    pub status: u8,
    /// Pairing URI to QR-encode + show to target user.  Empty on error.
    pub uri: String,
    /// Human-readable detail.
    pub detail: String,
}

/// Reply for `handle_hello` / `handle_cert` paths — carries OOB code +
/// opaque ceremony bytes (Cert on Source.handle_hello; empty on
/// Target.handle_cert).  Epic 489.8.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairOobReply {
    pub status: u8,
    /// 6-digit ASCII OOB code (zero-filled on non-OK).
    pub oob_code: [u8; 6],
    /// Cert bytes (Source.handle_hello) or empty (Target.handle_cert).
    pub response_bytes: Vec<u8>,
    pub detail: String,
}

/// Status-only reply (Source.handle_confirm).  Epic 489.8.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairStatusReply {
    pub status: u8,
    pub detail: String,
}

/// Reply carrying status + opaque bytes.  Used by
/// `target_consume_uri` (Hello bytes) and `target_build_confirm`
/// (Confirm bytes).  Epic 489.8.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairFrameReply {
    pub status: u8,
    pub bytes: Vec<u8>,
    pub detail: String,
}

/// Reply [`VeilClient::create_bootstrap_invite`] (Epic 489.7
/// generator side) — UI-friendly wrapper over
/// `veil_proto::CreateBootstrapInviteResultPayload`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateBootstrapInviteReply {
    /// Wire-byte status — see `veil_proto::create_invite_status`
    /// constants (OK / NOT_CONFIGURED / BAD_PASSWORD / INTERNAL_ERROR).
    pub status: u8,
    /// Encoded invite URI on success; empty on error.
    pub uri: String,
    /// Human-readable detail (best-effort UTF-8 from a fallible decode
    /// of the bytes the daemon sent; lossy if future status codes
    /// ship non-UTF-8 debug data).
    pub detail: String,
}

/// One entry [`VeilClient::peers`] — UI-friendly wrapper over
/// `veil_proto::PeersListEntry`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerEntry {
    /// Peer's `node_id`.
    pub node_id: [u8; 32],
    /// Wire-byte session state — see `veil_proto::peer_state` constants.
    pub state: u8,
    /// Wire-byte direction — see `veil_proto::peer_direction` constants.
    pub direction: u8,
    /// Transport URI (e.g. `tcp://1.2.3.4:5555`).
    pub transport: String,
}

/// Reply returned by [`VeilClient::mailbox_put`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MailboxPutReply {
    /// Outcome of the put.
    pub status: veilcore::proto::MailboxPutStatus,
    /// Number of older blobs evicted to make room. Only nonzero on
    /// `Stored` when the global quota was the binding constraint.
    pub evicted: u32,
}

/// One verified replica candidate returned by
/// [`VeilClient::lookup_rendezvous_replicas`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RendezvousReplicaInfo {
    /// Relay's `node_id`. Sender targets this for `MailboxPut` over
    /// the veil app-message channel using `MAILBOX_APP_ID`.
    pub relay_node_id: [u8; 32],
    /// Unix-seconds when the receiver's RendezvousAd expires. Stale
    /// after this; sender should re-lookup.
    pub valid_until_unix: u64,
    /// Sealed FCM/APNs envelope to attach to the put. May be empty
    /// (receiver did not register push — relay only stores).
    pub push_envelope: Vec<u8>,
    /// receiver-signed mailbox capability
    /// token to forward in [`VeilClient::mailbox_put`]. Empty when
    /// the receiver did not mint one (legacy senders / hybrid identities
    /// / pre-slice-2 daemons / relays running with the default
    /// `require_capability_token = false`).
    pub capability_token: Vec<u8>,
    /// Sealed `WakeHmacKey` envelope (Epic 489.10 slice 2b) copied verbatim
    /// from the receiver's resolved `RendezvousAd.wake_hmac_envelope`. Forward
    /// it as the `wake_hmac_envelope` argument to
    /// [`VeilClient::mailbox_put`] so the relay can mint a receiver-
    /// verifiable wake-HMAC tag. Empty when the receiver did not register for
    /// wake-HMAC (legacy receivers / pre-slice-2b daemons); pass `None` to
    /// `mailbox_put` in that case and the relay falls back to an
    /// unauthenticated wake.
    pub wake_hmac_envelope: Vec<u8>,
}

/// One outbox entry returned by [`VeilClient::outbox_find_missing`]
///
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxEntryInfo {
    /// Caller-chosen content id.
    pub content_id: [u8; 32],
    /// Unix-seconds deposit timestamp.
    pub deposited_at: u64,
    /// Encrypted blob the sender wants to retransmit.
    pub blob: Vec<u8>,
}

/// One blob returned by [`VeilClient::mailbox_fetch`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxBlobInfo {
    /// Sender's `node_id` (recorded by the relay at put-time).
    pub sender_id: [u8; 32],
    /// Caller-chosen content id (used for ack and dedup).
    pub content_id: [u8; 32],
    /// Unix-seconds deposit timestamp.
    pub deposited_at: u64,
    /// Encrypted payload (caller decrypts with end-to-end key).
    pub blob: Vec<u8>,
}

/// Peer P-Net admission status returned by
/// [`VeilClient::peer_pnet_status`].  Surfaces whether the daemon
/// has an active session to the queried peer and (when P-Net is enabled)
/// the verified MembershipCert details.
///
/// Use by app-layer admission gates (ogate / oproxy) to delegate cert
/// verification to the daemon instead of maintaining their own static
/// `allowed_node_ids` list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PnetStatus {
    /// `true` ⇒ daemon has an active veil session to this peer.
    pub admitted: bool,
    /// `true` ⇒ daemon verified a MembershipCert for this peer at
    /// handshake time.  `false` when daemon is in public mode or
    /// the session predates cert verification.
    pub has_cert: bool,
    /// Cert admin flag (only meaningful when `has_cert == true`).
    pub admin: bool,
    /// Cert expiry. `0` ⇒ sentinel "no expiry"; otherwise unix seconds.
    /// Meaningful only when `has_cert == true`.
    pub valid_until_unix: u64,
    /// Cert's network_id (zeros when `has_cert == false`).
    pub network_id: [u8; 32],
    /// Echoes the queried peer_node_id for correlation in pipelined IPC.
    pub peer_node_id: [u8; 32],
}

/// Daemon identity returned by [`VeilClient::node_identity`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeIdentity {
    /// Daemon's `node_id = BLAKE3(public_key)`.
    pub node_id: [u8; 32],
    /// Signature-algorithm wire byte (matches `veil_types::SignatureAlgorithm::wire_byte`).
    pub algo: u8,
    /// Raw signing public-key bytes (length depends on `algo`: Ed25519 = 32 B
    /// Falcon-512 ≈ 897 B). May be empty if the daemon couldn't decode its
    /// own pubkey at IPC-server startup — in that case the `node_id` is
    /// still authoritative.
    pub public_key: Vec<u8>,
    ///.4 P0: the daemon's relay-side X25519
    /// public key. Apps that want to seal a push-envelope (FCM/APNs
    /// token) for this relay use this exact key with
    /// `veilclient::push_envelope::seal` (or the equivalent in
    /// veil-anonymity). `None` means the daemon is not relay-
    /// capable — apps must pick a different relay for sealing. Old
    /// daemons (pre-T1.4) also report `None` because they don't
    /// populate the optional trailer.
    pub relay_x25519_pubkey: Option<[u8; 32]>,
}

// ── Reader task ───────────────────────────────────────────────────────────────

async fn reader_task(
    mut rh: IpcReadHalf,
    dispatch: Arc<Mutex<DispatchTable>>,
    writer: SharedWriter,
) {
    loop {
        let (hdr, body) = match read_frame_rh(&mut rh).await {
            Ok(f) => f,
            Err(_) => break, // connection closed
        };

        let msg_type = match LocalAppMsg::try_from(hdr.msg_type) {
            Ok(m) => m,
            Err(_) => continue,
        };

        match msg_type {
            LocalAppMsg::AppBindOk => {
                if let Ok(ok) = AppBindOkPayload::decode(&body) {
                    let mut d = dispatch.lock().await;
                    if let Some(tx) = pop_next_open(&mut d.pending_binds) {
                        let _ = tx.send(Ok(ok));
                    }
                }
            }
            LocalAppMsg::AppBindErr => {
                use veilcore::proto::AppBindErrPayload;
                if let Ok(err) = AppBindErrPayload::decode(&body) {
                    let mut d = dispatch.lock().await;
                    if let Some(tx) = pop_next_open(&mut d.pending_binds) {
                        let _ = tx.send(Err(ClientError::Bind {
                            code: err.error_code,
                            detail: String::from_utf8_lossy(&err.detail).into_owned(),
                        }));
                    }
                }
            }
            LocalAppMsg::AppDeliver => {
                use veilcore::proto::AppDeliverPayload;
                if let Ok(p) = AppDeliverPayload::decode(&body) {
                    let d = dispatch.lock().await;
                    if let Some(tx) = d.endpoints.get(&p.endpoint_id) {
                        // try_send → drop on full. Matches the daemon's
                        // drop-on-overflow semantics; keeps memory bounded
                        // when the application thread can't drain in time.
                        let _ = tx.try_send(crate::handle::IncomingMessage {
                            src_node_id: p.src_node_id,
                            src_app_id: p.src_app_id,
                            // d: wire payload is `PooledShared` (refcounted
                            // pool buffer); SDK boundary copies into owned `Vec<u8>`
                            // so user-side ownership is unambiguous. The pool slot
                            // returns when `p` drops at end of this arm.
                            data: p.data.to_vec(),
                            reply_id: p.reply_id,
                        });
                    }
                }
            }
            LocalAppMsg::StreamOpenOk => {
                use veilcore::proto::StreamOpenOkPayload;
                if let Ok(ok) = StreamOpenOkPayload::decode(&body) {
                    let mut d = dispatch.lock().await;
                    // audit cycle-6 (P3 review): consume EXACTLY the front waiter
                    // (FIFO). StreamOpen replies have no correlation id, so the
                    // daemon's reply order = request order is the only matching
                    // mechanism. If the front waiter abandoned (timed out via
                    // STREAM_OPEN_TIMEOUT, or was cancelled — its oneshot is
                    // closed), DISCARD this reply rather than skipping the slot
                    // and mis-delivering it to a different live waiter (which
                    // would connect that caller to the WRONG destination). The
                    // daemon GCs the orphaned stream via its own idle timeout.
                    if let Some((tx, data_tx)) = d.pending_stream_opens.pop_front() {
                        if tx.is_closed() {
                            // Waiter gone — drop the reply (and its data_tx) on
                            // the floor; do NOT register d.streams[stream_id].
                        } else {
                            // Insert stream channel BEFORE resolving the oneshot
                            // so StreamData frames arriving immediately are not lost.
                            d.streams.insert(ok.stream_id, data_tx);
                            let _ = tx.send(Ok(ok.stream_id));
                        }
                    }
                }
            }
            LocalAppMsg::StreamOpenInbound => {
                // Phase 6.51: inbound-stream notification from daemon.
                // Build the data-channel pair, register the stream-id,
                // wrap as VeilStream, and hand off to the bound
                // endpoint's accept_stream queue.
                use veilcore::proto::StreamOpenInboundPayload;
                if let Ok(p) = StreamOpenInboundPayload::decode(&body) {
                    let (data_tx, data_rx) = mpsc::channel::<StreamEvent>(STREAM_EVENT_QUEUE_CAP);
                    let mut d = dispatch.lock().await;
                    // Find the bound endpoint's inbound-stream queue.
                    if let Some(q) = d.inbound_streams.get(&p.endpoint_id).cloned() {
                        d.streams.insert(p.stream_id, data_tx);
                        drop(d); // release lock before sending.
                        let veil_stream =
                            crate::stream::VeilStream::new(p.stream_id, writer.clone(), data_rx);
                        let incoming = crate::handle::IncomingStream {
                            stream: veil_stream,
                            src_node_id: p.src_node_id,
                        };
                        // `try_send` (not `send().await`) so a slow
                        // `accept_stream` consumer cannot block the
                        // reader task that drives EVERY stream on this
                        // IPC connection.  On `Full`/`Closed` the
                        // notification cannot be delivered — audit cycle-8:
                        // we MUST then undo the `d.streams.insert` above
                        // (else the stream-id is orphaned client-side until
                        // the daemon idle-times-it-out) AND proactively send
                        // a StreamClose so the daemon tears down its side now
                        // instead of waiting for that timeout.
                        if q.try_send(incoming).is_err() {
                            dispatch.lock().await.streams.remove(&p.stream_id);
                            let close = veilcore::proto::StreamClosePayload {
                                stream_id: p.stream_id,
                            };
                            let _ = writer
                                .write_frame(LocalAppMsg::StreamClose as u16, &close.encode())
                                .await;
                        }
                    }
                    // No matching endpoint — drop silently (matches the
                    // existing pattern for AppDeliver to a closed
                    // endpoint).  Reader task can't depend on `log`
                    // because the SDK is `no-deps`-friendly.
                }
            }
            LocalAppMsg::StreamOpenErr => {
                use veilcore::proto::StreamOpenErrPayload;
                if let Ok(err) = StreamOpenErrPayload::decode(&body) {
                    let mut d = dispatch.lock().await;
                    // audit cycle-6 (P3 review): consume the front waiter (FIFO);
                    // if it abandoned (closed), discard the error rather than
                    // mis-delivering it to a different live waiter (see
                    // StreamOpenOk above).
                    if let Some((tx, _data_tx)) = d.pending_stream_opens.pop_front()
                        && !tx.is_closed()
                    {
                        let _ = tx.send(Err(ClientError::StreamOpen {
                            code: err.error_code,
                        }));
                    }
                }
            }
            LocalAppMsg::StreamData => {
                use veilcore::proto::StreamDataPayload;
                if let Ok(p) = StreamDataPayload::decode(&body) {
                    let mut d = dispatch.lock().await;
                    let stream_id = p.stream_id;
                    let mut close_stream = false;
                    if let Some(tx) = d.streams.get(&stream_id) {
                        // `try_send` (not `.await`) so a slow consumer
                        // on ONE stream cannot stall the global reader
                        // task (and every other stream on this IPC
                        // connection).  On `Full` the consumer is
                        // demonstrably falling behind the daemon's
                        // delivery rate — close the stream so the
                        // consumer surfaces EOF (`recv()` → None) and
                        // any further frames on the wire get sent a
                        // STREAM_CLOSE by the daemon.
                        if let Err(tokio::sync::mpsc::error::TrySendError::Full(_)) =
                            tx.try_send(StreamEvent::Data(p.data))
                        {
                            close_stream = true;
                        }
                        // `Closed` variant = consumer already dropped
                        // VeilStream; nothing to do (next STREAM_CLOSE
                        // from daemon will clean the table entry).
                    }
                    if close_stream {
                        d.streams.remove(&stream_id);
                        // Sender drop here makes the consumer's `recv()`
                        // return None on the next poll = EOF, matching
                        // the StreamEvent::Close handling in stream.rs.
                    }
                }
            }
            LocalAppMsg::StreamClose => {
                use veilcore::proto::StreamClosePayload;
                if let Ok(p) = StreamClosePayload::decode(&body) {
                    let mut d = dispatch.lock().await;
                    if let Some(tx) = d.streams.remove(&p.stream_id) {
                        // `try_send`: on a full queue we simply drop
                        // the Close event — the sender goes out of
                        // scope after `remove`, so the consumer sees
                        // `recv()` → None which the stream-reader
                        // already maps to EOF (see. stream.rs:104).
                        let _ = tx.try_send(StreamEvent::Close);
                    }
                }
            }
            LocalAppMsg::NodeIdentity => {
                // deliver to oldest pending oneshot. Malformed
                // payloads silently drop the waiter (caller's await
                // resolves with ConnectionClosed) — daemon shouldn't be
                // sending bad replies, so this is a defensive escape hatch
                // not a normal path.
                use veilcore::proto::NodeIdentityPayload;
                if let Ok(p) = NodeIdentityPayload::decode(&body) {
                    let mut d = dispatch.lock().await;
                    if let Some(tx) = pop_next_open(&mut d.pending_node_identity) {
                        let _ = tx.send(NodeIdentity {
                            node_id: p.node_id,
                            algo: p.algo,
                            public_key: p.public_key,
                            relay_x25519_pubkey: p.relay_x25519_pubkey,
                        });
                    }
                }
            }
            LocalAppMsg::PeersList => {
                use veilcore::proto::PeersListPayload;
                if let Ok(p) = PeersListPayload::decode(&body) {
                    let entries: Vec<PeerEntry> = p
                        .peers
                        .into_iter()
                        .map(|e| PeerEntry {
                            node_id: e.node_id,
                            state: e.state,
                            direction: e.direction,
                            // Best-effort UTF-8 decode of transport URI. Lossy
                            // fallback handles a wire bug where the daemon
                            // emits invalid bytes — UI sees `…` placeholder
                            // for that one peer rather than failing the
                            // whole list.
                            transport: String::from_utf8_lossy(&e.transport).into_owned(),
                        })
                        .collect();
                    let mut d = dispatch.lock().await;
                    if let Some(tx) = pop_next_open(&mut d.pending_peers_list) {
                        let _ = tx.send(entries);
                    }
                }
            }
            LocalAppMsg::PnetStatusResult => {
                use veilcore::proto::PnetStatusResultPayload;
                if let Ok(p) = PnetStatusResultPayload::decode(&body) {
                    let status = PnetStatus {
                        admitted: p.admitted,
                        has_cert: p.has_cert,
                        admin: p.admin,
                        valid_until_unix: p.valid_until_unix,
                        network_id: p.network_id,
                        peer_node_id: p.peer_node_id,
                    };
                    let mut d = dispatch.lock().await;
                    if let Some(tx) = pop_next_open(&mut d.pending_pnet_status) {
                        let _ = tx.send(status);
                    }
                }
            }
            LocalAppMsg::SetPushEnvelopeOk => {
                //.2: 1-byte status response.
                if !body.is_empty()
                    && let Ok(status) = veilcore::proto::SetPushEnvelopeStatus::from_wire(body[0])
                {
                    let mut d = dispatch.lock().await;
                    if let Some(tx) = pop_next_open(&mut d.pending_set_push_envelope) {
                        let _ = tx.send(status);
                    }
                }
            }
            LocalAppMsg::SetWakeHmacEnvelopeOk => {
                // slice 4.3.4: 1-byte status response (analog to SetPushEnvelopeOk).
                if !body.is_empty()
                    && let Ok(status) =
                        veilcore::proto::SetWakeHmacEnvelopeStatus::from_wire(body[0])
                {
                    let mut d = dispatch.lock().await;
                    if let Some(tx) = pop_next_open(&mut d.pending_set_wake_hmac_envelope) {
                        let _ = tx.send(status);
                    }
                }
            }
            LocalAppMsg::RegisterOnionServiceResult if body.len() >= 2 => {
                let status = u16::from_be_bytes([body[0], body[1]]);
                let mut d = dispatch.lock().await;
                if let Some(tx) = pop_next_open(&mut d.pending_register_onion_service) {
                    let _ = tx.send(status);
                }
            }
            LocalAppMsg::MailboxPutOk => {
                use veilcore::proto::MailboxPutOkPayload;
                if let Ok(p) = MailboxPutOkPayload::decode(&body) {
                    let mut d = dispatch.lock().await;
                    if let Some(tx) = pop_next_open(&mut d.pending_mailbox_put) {
                        let _ = tx.send(MailboxPutReply {
                            status: p.status,
                            evicted: p.evicted,
                        });
                    }
                }
            }
            LocalAppMsg::MailboxFetchResp => {
                use veilcore::proto::MailboxFetchRespPayload;
                if let Ok(p) = MailboxFetchRespPayload::decode(&body) {
                    let blobs: Vec<MailboxBlobInfo> = p
                        .blobs
                        .into_iter()
                        .map(|b| MailboxBlobInfo {
                            sender_id: b.sender_id,
                            content_id: b.content_id,
                            deposited_at: b.deposited_at,
                            blob: b.blob,
                        })
                        .collect();
                    let mut d = dispatch.lock().await;
                    if let Some(tx) = pop_next_open(&mut d.pending_mailbox_fetch) {
                        let _ = tx.send(blobs);
                    }
                }
            }
            LocalAppMsg::MailboxAckOk if !body.is_empty() => {
                let removed = body[0] != 0;
                let mut d = dispatch.lock().await;
                if let Some(tx) = pop_next_open(&mut d.pending_mailbox_ack) {
                    let _ = tx.send(removed);
                }
            }
            LocalAppMsg::OutboxPutOk if !body.is_empty() => {
                let stored = body[0] != 0;
                let mut d = dispatch.lock().await;
                if let Some(tx) = pop_next_open(&mut d.pending_outbox_put) {
                    let _ = tx.send(stored);
                }
            }
            LocalAppMsg::OutboxFindMissingResp => {
                use veilcore::proto::OutboxFindMissingRespPayload;
                if let Ok(p) = OutboxFindMissingRespPayload::decode(&body) {
                    let entries: Vec<OutboxEntryInfo> = p
                        .entries
                        .into_iter()
                        .map(|e| OutboxEntryInfo {
                            content_id: e.content_id,
                            deposited_at: e.deposited_at,
                            blob: e.blob,
                        })
                        .collect();
                    let mut d = dispatch.lock().await;
                    if let Some(tx) = pop_next_open(&mut d.pending_outbox_find_missing) {
                        let _ = tx.send(entries);
                    }
                }
            }
            LocalAppMsg::OutboxAckOk if !body.is_empty() => {
                let removed = body[0] != 0;
                let mut d = dispatch.lock().await;
                if let Some(tx) = pop_next_open(&mut d.pending_outbox_ack) {
                    let _ = tx.send(removed);
                }
            }
            LocalAppMsg::LookupRendezvousReplicasResp => {
                use veilcore::proto::LookupRendezvousReplicasRespPayload;
                if let Ok(p) = LookupRendezvousReplicasRespPayload::decode(&body) {
                    let entries: Vec<RendezvousReplicaInfo> = p
                        .entries
                        .into_iter()
                        .map(|e| RendezvousReplicaInfo {
                            relay_node_id: e.relay_node_id,
                            valid_until_unix: e.valid_until_unix,
                            push_envelope: e.push_envelope,
                            capability_token: e.capability_token,
                            wake_hmac_envelope: e.wake_hmac_envelope,
                        })
                        .collect();
                    let mut d = dispatch.lock().await;
                    if let Some(tx) = pop_next_open(&mut d.pending_lookup_replicas) {
                        let _ = tx.send(entries);
                    }
                }
            }
            LocalAppMsg::MobileStatus => {
                use veilcore::proto::MobileStatusPayload;
                if let Ok(p) = MobileStatusPayload::decode(&body) {
                    let status = MobileStatus {
                        background_tier: p.background_tier,
                        background_keepalive_multiplier: p.background_keepalive_multiplier,
                        background_keepalive_factor: p.background_keepalive_factor,
                        battery_level_pct: p.battery_level_pct,
                        low_battery_threshold_pct: p.low_battery_threshold_pct,
                        low_battery_multiplier: p.low_battery_multiplier,
                        battery_route_probe_factor: p.battery_route_probe_factor,
                    };
                    let mut d = dispatch.lock().await;
                    if let Some(tx) = pop_next_open(&mut d.pending_mobile_status) {
                        let _ = tx.send(status);
                    }
                }
            }
            LocalAppMsg::JoinBootstrapResult => {
                use veilcore::proto::JoinBootstrapResultPayload;
                if let Ok(p) = JoinBootstrapResultPayload::decode(&body) {
                    let result = JoinBootstrapResult {
                        status: p.status,
                        peer_node_id: p.peer_node_id,
                        detail: String::from_utf8_lossy(&p.detail).into_owned(),
                    };
                    let mut d = dispatch.lock().await;
                    if let Some(tx) = pop_next_open(&mut d.pending_bootstrap_join) {
                        let _ = tx.send(result);
                    }
                }
            }
            LocalAppMsg::CreateBootstrapInviteResult => {
                use veilcore::proto::CreateBootstrapInviteResultPayload;
                if let Ok(p) = CreateBootstrapInviteResultPayload::decode(&body) {
                    let reply = CreateBootstrapInviteReply {
                        status: p.status,
                        uri: p.uri,
                        detail: String::from_utf8_lossy(&p.detail).into_owned(),
                    };
                    let mut d = dispatch.lock().await;
                    if let Some(tx) = pop_next_open(&mut d.pending_create_invite) {
                        let _ = tx.send(reply);
                    }
                }
            }
            LocalAppMsg::PairSourceCreateInviteResult => {
                use veilcore::proto::PairSourceCreateInviteResultPayload;
                if let Ok(p) = PairSourceCreateInviteResultPayload::decode(&body) {
                    let reply = PairCreateInviteReply {
                        status: p.status,
                        uri: p.uri,
                        detail: String::from_utf8_lossy(&p.detail).into_owned(),
                    };
                    let mut d = dispatch.lock().await;
                    if let Some(tx) = pop_next_open(&mut d.pending_pair_source_create) {
                        let _ = tx.send(reply);
                    }
                }
            }
            LocalAppMsg::PairSourceHandleHelloResult => {
                use veilcore::proto::PairCeremonyOobResultPayload;
                if let Ok(p) = PairCeremonyOobResultPayload::decode(&body) {
                    let reply = PairOobReply {
                        status: p.status,
                        oob_code: p.oob_code,
                        response_bytes: p.response_bytes,
                        detail: String::from_utf8_lossy(&p.detail).into_owned(),
                    };
                    let mut d = dispatch.lock().await;
                    if let Some(tx) = pop_next_open(&mut d.pending_pair_source_hello) {
                        let _ = tx.send(reply);
                    }
                }
            }
            LocalAppMsg::PairSourceHandleConfirmResult => {
                use veilcore::proto::PairStatusResultPayload;
                if let Ok(p) = PairStatusResultPayload::decode(&body) {
                    let reply = PairStatusReply {
                        status: p.status,
                        detail: String::from_utf8_lossy(&p.detail).into_owned(),
                    };
                    let mut d = dispatch.lock().await;
                    if let Some(tx) = pop_next_open(&mut d.pending_pair_source_confirm) {
                        let _ = tx.send(reply);
                    }
                }
            }
            LocalAppMsg::PairTargetConsumeUriResult => {
                use veilcore::proto::PairCeremonyFrameResultPayload;
                if let Ok(p) = PairCeremonyFrameResultPayload::decode(&body) {
                    let reply = PairFrameReply {
                        status: p.status,
                        bytes: p.bytes,
                        detail: String::from_utf8_lossy(&p.detail).into_owned(),
                    };
                    let mut d = dispatch.lock().await;
                    if let Some(tx) = pop_next_open(&mut d.pending_pair_target_consume) {
                        let _ = tx.send(reply);
                    }
                }
            }
            LocalAppMsg::PairTargetHandleCertResult => {
                use veilcore::proto::PairCeremonyOobResultPayload;
                if let Ok(p) = PairCeremonyOobResultPayload::decode(&body) {
                    let reply = PairOobReply {
                        status: p.status,
                        oob_code: p.oob_code,
                        response_bytes: p.response_bytes,
                        detail: String::from_utf8_lossy(&p.detail).into_owned(),
                    };
                    let mut d = dispatch.lock().await;
                    if let Some(tx) = pop_next_open(&mut d.pending_pair_target_cert) {
                        let _ = tx.send(reply);
                    }
                }
            }
            LocalAppMsg::PairTargetBuildConfirmResult => {
                use veilcore::proto::PairCeremonyFrameResultPayload;
                if let Ok(p) = PairCeremonyFrameResultPayload::decode(&body) {
                    let reply = PairFrameReply {
                        status: p.status,
                        bytes: p.bytes,
                        detail: String::from_utf8_lossy(&p.detail).into_owned(),
                    };
                    let mut d = dispatch.lock().await;
                    if let Some(tx) = pop_next_open(&mut d.pending_pair_target_confirm) {
                        let _ = tx.send(reply);
                    }
                }
            }
            LocalAppMsg::Event => {
                // forward to the single subscriber if any.
                // No subscriber == events silently dropped, which is the
                // expected behaviour: the daemon doesn't know whether
                // any given client cares, so it always publishes.
                use veilcore::proto::EventPayload;
                if let Ok(p) = EventPayload::decode(&body) {
                    let event = VeilEvent {
                        kind: p.kind,
                        payload: p.payload,
                    };
                    let mut d = dispatch.lock().await;
                    let drop_sink = if let Some(tx) = d.event_sink.as_ref() {
                        // `try_send` returns Err if either the receiver
                        // is gone OR the channel is full. Both cases ⇒
                        // drop the event and (if closed) clear the sender.
                        match tx.try_send(event) {
                            Ok(()) => false,
                            Err(mpsc::error::TrySendError::Closed(_)) => true,
                            Err(mpsc::error::TrySendError::Full(_)) => false,
                        }
                    } else {
                        false
                    };
                    if drop_sink {
                        d.event_sink = None;
                    }
                }
            }
            _ => {}
        }
    }

    // audit cycle-6 (P3): the read loop only exits when the IPC connection is
    // closed (daemon death / socket error). Drain every pending stream-open
    // waiter and fail it with `ConnectionClosed` so callers blocked in
    // `open_stream` return immediately instead of waiting out
    // `STREAM_OPEN_TIMEOUT`. (Other pending-RPC queues already wrap their await
    // in `recv_with_timeout`, so the stream-open queue is the one that needs an
    // explicit drain here.)
    {
        let mut d = dispatch.lock().await;
        while let Some((tx, _data_tx)) = d.pending_stream_opens.pop_front() {
            let _ = tx.send(Err(ClientError::ConnectionClosed));
        }
    }
}

// ── Frame I/O helpers ─────────────────────────────────────────────────────────

/// Hard upper-bound on how long a frame BODY may take to arrive after its
/// header was read. Mirrors the daemon-side `BODY_READ_DEADLINE` in
/// `veil-ipc::frame_io`: without it a fake/compromised daemon could announce a
/// body of up to `MAX_FRAME_BODY` (16 MiB) and then never send it, pinning the
/// SDK's reader task and the allocated buffer indefinitely. Only the body is
/// bounded — the header read is left unbounded because an idle connection
/// legitimately waits (possibly minutes) for the next frame.
const IPC_BODY_READ_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);

pub(crate) async fn read_frame_raw(
    stream: &mut IpcStream,
) -> Result<(FrameHeader, Vec<u8>), ClientError> {
    let mut hdr_buf = [0u8; veilcore::proto::HEADER_SIZE];
    stream.read_exact(&mut hdr_buf).await?;
    let hdr = codec::decode_header(&hdr_buf).map_err(|e| ClientError::Protocol(e.to_string()))?;
    if hdr.body_len > veilcore::proto::codec::MAX_FRAME_BODY {
        return Err(ClientError::Protocol(format!(
            "frame body_len {} exceeds limit {}",
            hdr.body_len,
            veilcore::proto::codec::MAX_FRAME_BODY,
        )));
    }
    let mut body = vec![0u8; hdr.body_len as usize];
    if !body.is_empty() {
        match tokio::time::timeout(IPC_BODY_READ_DEADLINE, stream.read_exact(&mut body)).await {
            Ok(io_result) => {
                io_result?;
            }
            Err(_elapsed) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!(
                        "IPC frame body read timeout after {}s (header announced {} body bytes)",
                        IPC_BODY_READ_DEADLINE.as_secs(),
                        hdr.body_len,
                    ),
                )
                .into());
            }
        }
    }
    Ok((hdr, body))
}

pub(crate) async fn read_frame_rh(
    rh: &mut IpcReadHalf,
) -> Result<(FrameHeader, Vec<u8>), ClientError> {
    let mut hdr_buf = [0u8; veilcore::proto::HEADER_SIZE];
    rh.read_exact(&mut hdr_buf).await?;
    let hdr = codec::decode_header(&hdr_buf).map_err(|e| ClientError::Protocol(e.to_string()))?;
    if hdr.body_len > veilcore::proto::codec::MAX_FRAME_BODY {
        return Err(ClientError::Protocol(format!(
            "frame body_len {} exceeds limit {}",
            hdr.body_len,
            veilcore::proto::codec::MAX_FRAME_BODY,
        )));
    }
    let mut body = vec![0u8; hdr.body_len as usize];
    if !body.is_empty() {
        match tokio::time::timeout(IPC_BODY_READ_DEADLINE, rh.read_exact(&mut body)).await {
            Ok(io_result) => {
                io_result?;
            }
            Err(_elapsed) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!(
                        "IPC frame body read timeout after {}s (header announced {} body bytes)",
                        IPC_BODY_READ_DEADLINE.as_secs(),
                        hdr.body_len,
                    ),
                )
                .into());
            }
        }
    }
    Ok((hdr, body))
}

pub(crate) async fn write_frame_raw(
    stream: &mut IpcStream,
    family: u8,
    msg_type: u16,
    body: &[u8],
) -> Result<(), ClientError> {
    let mut hdr = FrameHeader::new(family, msg_type);
    hdr.body_len = body.len() as u32;
    stream.write_all(&codec::encode_header(&hdr)).await?;
    if !body.is_empty() {
        stream.write_all(body).await?;
    }
    Ok(())
}

/// Connect to the IPC server at `anchor` using whichever backend the node
/// is currently bound to.
///
/// Probe order:
/// 1. If `anchor`'s parent dir contains both `ipc.port` and `ipc.token`
///    treat as TCP-loopback: read the port + 32-byte token, connect to
///    `127.0.0.1:port`, send the token as the first frame.
/// 2. Otherwise treat `anchor` as the Unix-socket path directly.
///
/// This is the same heuristic the admin client uses for its own backends —
/// keeps app code working unchanged when the operator switches Unix↔TCP.
pub async fn connect_ipc_any(anchor: &Path) -> Result<IpcStream, ClientError> {
    use veil_ipc::path::{IPC_PORT_FILENAME, IPC_TOKEN_FILENAME};
    if let Some(parent) = anchor.parent() {
        let port_path = parent.join(IPC_PORT_FILENAME);
        let token_path = parent.join(IPC_TOKEN_FILENAME);
        if port_path.exists() && token_path.exists() {
            let port_str = tokio::fs::read_to_string(&port_path)
                .await
                .map_err(ClientError::Io)?;
            let port: u16 = port_str.trim().parse().map_err(|e| {
                ClientError::Protocol(format!(
                    "ipc.port at {} contains invalid port: {e}",
                    port_path.display()
                ))
            })?;
            let token_hex = tokio::fs::read_to_string(&token_path)
                .await
                .map_err(ClientError::Io)?;
            let token = transport::IpcToken::from_hex(token_hex.trim()).map_err(ClientError::Io)?;
            let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().map_err(|e| {
                ClientError::Protocol(format!("ipc.port → invalid SocketAddr: {e}"))
            })?;
            return transport::connect_tcp(addr, &token)
                .await
                .map_err(ClientError::Io);
        }

        // NamedPipe probe (Windows). When `ipc.pipe` + `ipc.token`
        // are present, the server is on a NamedPipe; read the pipe name from
        // the sidecar, then connect.
        #[cfg(windows)]
        {
            use veil_ipc::path::IPC_PIPE_FILENAME;
            let pipe_path = parent.join(IPC_PIPE_FILENAME);
            if pipe_path.exists() && token_path.exists() {
                let pipe_name = tokio::fs::read_to_string(&pipe_path)
                    .await
                    .map_err(ClientError::Io)?;
                let token_hex = tokio::fs::read_to_string(&token_path)
                    .await
                    .map_err(ClientError::Io)?;
                let token =
                    transport::IpcToken::from_hex(token_hex.trim()).map_err(ClientError::Io)?;
                return transport::connect_named_pipe(pipe_name.trim(), &token)
                    .await
                    .map_err(ClientError::Io);
            }
        }
    }
    transport::connect_unix(anchor)
        .await
        .map_err(ClientError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// audit cycle-6 (P3 review): consume-one FIFO matching must NOT misroute a
    /// reply. With queue [abandoned_A, live_B], the FIRST StreamOpenOk (which by
    /// FIFO belongs to A) must be discarded — NOT delivered to B — and B's own
    /// (second) reply must then reach B. This replicates the StreamOpenOk
    /// handler's pop_front + is_closed-discard logic.
    #[test]
    fn consume_one_discards_abandoned_reply_does_not_misroute() {
        let mut q: std::collections::VecDeque<PendingStreamOpen> =
            std::collections::VecDeque::new();

        // Front waiter A abandoned (timed out / cancelled): drop its receiver.
        let (tx_a, rx_a) = tokio::sync::oneshot::channel::<Result<u32, ClientError>>();
        let (data_tx_a, _data_rx_a) = mpsc::channel::<StreamEvent>(STREAM_EVENT_QUEUE_CAP);
        drop(rx_a);
        q.push_back((tx_a, data_tx_a));

        // Live waiter B.
        let (tx_b, mut rx_b) = tokio::sync::oneshot::channel::<Result<u32, ClientError>>();
        let (data_tx_b, _data_rx_b) = mpsc::channel::<StreamEvent>(STREAM_EVENT_QUEUE_CAP);
        q.push_back((tx_b, data_tx_b));

        // Reply #1 (FIFO → A's): pop front, A is closed → discard.
        let (tx, _data_tx) = q.pop_front().expect("front A");
        assert!(tx.is_closed(), "A abandoned");
        // (handler would discard here — do nothing)

        // B must NOT have received A's reply (no misroute).
        assert!(
            matches!(
                rx_b.try_recv(),
                Err(tokio::sync::oneshot::error::TryRecvError::Empty)
            ),
            "B must not be mis-delivered A's reply",
        );

        // Reply #2 (FIFO → B's): pop front, B is live → deliver stream_id 100.
        let (tx, _data_tx) = q.pop_front().expect("front B");
        assert!(!tx.is_closed(), "B live");
        let _ = tx.send(Ok(100));

        assert_eq!(
            rx_b.try_recv().unwrap().unwrap(),
            100,
            "B gets its OWN reply"
        );
        assert!(q.is_empty());
    }
}
