//! Per-endpoint application handle.

use std::sync::Arc;

use veilcore::proto::{AppIpcRtSendPayload, AppUnbindPayload, LocalAppMsg, StreamOpenPayload};

use crate::client::{DispatchTable, SharedWriter, StreamEvent};
use crate::error::ClientError;
use crate::stream::VeilStream;
use tokio::sync::{Mutex, mpsc};

/// A single incoming datagram delivered to this endpoint.
pub struct IncomingMessage {
    /// Node ID of the sender (32 bytes).
    pub src_node_id: [u8; 32],
    /// App ID of the sender on the originating node (32 bytes).
    pub src_app_id: [u8; 32],
    /// Raw payload bytes.
    pub data: Vec<u8>,
}

/// А remote peer opened а byte-stream к this endpoint.  Returned by
/// [`AppHandle::accept_stream`] / [`AppReceiver::accept_stream`].
pub struct IncomingStream {
    /// Live byte-pipe — implements `AsyncRead` + `AsyncWrite`.
    pub stream: crate::stream::VeilStream,
    /// 32-byte node_id of the peer that initiated the stream.
    pub src_node_id: [u8; 32],
}

/// RAII handle for a bound veil application endpoint.
///
/// Obtained [`VeilClient::bind`]. When dropped, the endpoint is
/// automatically unbound from the local veil node.
pub struct AppHandle {
    pub(crate) app_id: [u8; 32],
    pub(crate) endpoint_id: u32,
    pub(crate) writer: SharedWriter,
    pub(crate) dispatch: Arc<Mutex<DispatchTable>>,
    pub(crate) rx: mpsc::Receiver<IncomingMessage>,
    /// Inbound-stream notifications (Phase 6.51 follow-up — closes
    /// the SDK gap that prevented server-side proxy / mailbox / etc.
    /// от being built outside the daemon).  Populated by the
    /// reader-task dispatch when а remote peer opens а stream к
    /// this bound endpoint.
    pub(crate) inbound_streams_rx: mpsc::Receiver<IncomingStream>,
}

impl AppHandle {
    pub(crate) fn new(
        app_id: [u8; 32],
        endpoint_id: u32,
        writer: SharedWriter,
        dispatch: Arc<Mutex<DispatchTable>>,
        rx: mpsc::Receiver<IncomingMessage>,
        inbound_streams_rx: mpsc::Receiver<IncomingStream>,
    ) -> Self {
        Self {
            app_id,
            endpoint_id,
            writer,
            dispatch,
            rx,
            inbound_streams_rx,
        }
    }

    /// Wait для the next incoming stream opened by а remote peer.
    ///
    /// Returns `None` when the IPC connection k the daemon closes.
    /// Each accepted stream carries its initiator's `src_node_id`
    /// — callers что want к enforce an allowlist (server-side proxy
    /// authz, etc.) check it before bridging.
    pub async fn accept_stream(&mut self) -> Option<IncomingStream> {
        self.inbound_streams_rx.recv().await
    }

    /// Returns this endpoint's numeric ID.
    pub fn endpoint_id(&self) -> u32 {
        self.endpoint_id
    }

    /// Returns this endpoint's 32-byte app ID assigned by the node.
    pub fn app_id(&self) -> &[u8; 32] {
        &self.app_id
    }

    /// Split the handle into independent send/recv halves so an
    /// application can drain incoming messages on a dedicated tokio
    /// task while another task drives outbound sends — useful for
    /// high-cadence patterns where the receiving side must keep
    /// pace with the local daemon's delivery channel (which has a
    /// fixed `DELIVERY_CHANNEL_CAP` and disconnects clients that
    /// fail to drain).
    ///
    /// Returns `(AppSender, AppReceiver)`.  Both halves remain
    /// associated с the original endpoint binding; dropping either
    /// does NOT unbind (the binding lives until BOTH halves are
    /// dropped, plus any unbind frame the daemon expects).
    ///
    /// Audit batch 2026-05-25 phase M (cross-audit closure):
    /// `AppReceiver` carries both the datagram `rx` AND the inbound-
    /// stream `inbound_streams_rx`.  Pre-fix the split dropped
    /// `inbound_streams_rx` silently, leaving callers что had bound
    /// для server-side stream-accept (mailbox proxy, oproxy server,
    /// mesh bridge) без а way к dispatch on accept post-split.
    /// Now both receive-capabilities survive the split.
    pub fn into_split(self) -> (AppSender, AppReceiver) {
        // AppHandle has a Drop that sends UNBIND; we need to move
        // fields out without firing it (sender's Drop takes over the
        // unbind responsibility). ManuallyDrop suppresses the
        // original Drop, then we extract each field via ptr::read.
        // Safe because we read each field exactly once and never use
        // the wrapped value again.
        let wrapped = std::mem::ManuallyDrop::new(self);
        let app_id = wrapped.app_id;
        let endpoint_id = wrapped.endpoint_id;
        let writer = unsafe { std::ptr::read(&wrapped.writer) };
        let dispatch = unsafe { std::ptr::read(&wrapped.dispatch) };
        let rx = unsafe { std::ptr::read(&wrapped.rx) };
        let inbound_streams_rx = unsafe { std::ptr::read(&wrapped.inbound_streams_rx) };
        let sender = AppSender {
            app_id,
            endpoint_id,
            writer,
            dispatch,
        };
        let receiver = AppReceiver {
            rx,
            inbound_streams_rx,
        };
        (sender, receiver)
    }

    /// Send a datagram to a remote node's endpoint.
    ///
    /// * `dst_node_id` — 32-byte target node ID.
    /// * `dst_app_id` — 32-byte application ID on the target node.
    /// * `dst_endpoint_id` — target endpoint number on the remote application.
    /// * `data` — payload bytes.
    pub async fn send(
        &self,
        dst_node_id: [u8; 32],
        dst_app_id: [u8; 32],
        dst_endpoint_id: u32,
        data: &[u8],
    ) -> Result<(), ClientError> {
        self.send_owned(dst_node_id, dst_app_id, dst_endpoint_id, data.to_vec())
            .await
    }

    /// Zero-copy variant of [`Self::send`] that takes ownership of `data`.
    /// Routes through `SharedWriter::write_app_ipc_send_owned` for the
    /// single-buffer IPC encode hot path.
    pub async fn send_owned(
        &self,
        dst_node_id: [u8; 32],
        dst_app_id: [u8; 32],
        dst_endpoint_id: u32,
        data: Vec<u8>,
    ) -> Result<(), ClientError> {
        self.writer
            .write_app_ipc_send_owned(
                &dst_node_id,
                &self.app_id,
                &dst_app_id,
                dst_endpoint_id,
                0,
                &data,
            )
            .await
    }

    /// Receive the next incoming datagram, or `None` if the connection closed.
    pub async fn recv(&mut self) -> Result<Option<IncomingMessage>, ClientError> {
        Ok(self.rx.recv().await)
    }

    /// Send a real-time (RT) media frame to a remote node's endpoint.
    ///
    /// This is a fire-and-forget, loss-tolerant path for audio/video streams.
    /// The frame is delivered at `REALTIME` priority via the active veil
    /// session to `dst_node_id`; if no session exists the node returns an error.
    ///
    /// * `dst_node_id` — 32-byte target node ID.
    /// * `dst_app_id` — 32-byte application ID on the target node.
    /// * `dst_endpoint_id` — target endpoint number.
    /// * `seq` — monotonic sequence number (wrap-around ok).
    /// * `timestamp_us` — media-clock timestamp in microseconds.
    /// * `marker` — application-defined marker bit (e.g. last frame of talk-spurt).
    /// * `payload_type` — codec identifier (application-defined).
    /// * `data` — encoded media payload bytes.
    #[allow(clippy::too_many_arguments)]
    pub async fn send_rt_data(
        &self,
        dst_node_id: [u8; 32],
        dst_app_id: [u8; 32],
        dst_endpoint_id: u32,
        seq: u32,
        timestamp_us: u64,
        marker: u8,
        payload_type: u32,
        data: &[u8],
    ) -> Result<(), ClientError> {
        let payload = AppIpcRtSendPayload {
            dst_node_id,
            src_app_id: self.app_id,
            dst_app_id,
            endpoint_id: dst_endpoint_id,
            seq,
            timestamp_us,
            marker,
            payload_type,
            data: data.to_vec(),
        };
        self.writer
            .write_frame(LocalAppMsg::AppRtSend as u16, &payload.encode())
            .await
    }

    /// Open a bidirectional byte-stream to an endpoint.
    ///
    /// Works for both LOCAL (same-node) and **cross-node** endpoints. For a
    /// remote `dst_node_id` the daemon bridges the stream over the wire
    /// `AppOpen`/`AppData`/`AppClose` machinery — provided it was started with
    /// the IPC stream bridge wired (the full `NodeRuntime` does this). A daemon
    /// built without the bridge (a minimal / embedded setup) replies
    /// `stream_open_err::REMOTE_NOT_IMPLEMENTED` for a remote target and this
    /// returns `Err` (it never panics or hangs). Datagram
    /// [`send`](Self::send) is cross-node in every configuration. See
    /// `docs/en/PLAN_IPC_STREAM_FORWARDING.md` for the bridge design.
    ///
    /// * `dst_node_id` — 32-byte target node ID (local or remote).
    /// * `dst_app_id` — 32-byte app ID on the target node.
    /// * `dst_endpoint_id` — numeric endpoint on the target node.
    /// * `initial_window` — initial receive window in bytes.
    ///
    /// Returns an [`VeilStream`] that implements `AsyncRead + AsyncWrite`.
    pub async fn open_stream(
        &self,
        dst_node_id: [u8; 32],
        dst_app_id: [u8; 32],
        dst_endpoint_id: u32,
        initial_window: u32,
    ) -> Result<VeilStream, ClientError> {
        use tokio::sync::oneshot;

        let (tx, rx) = oneshot::channel::<Result<u32, ClientError>>();
        // Pre-create the stream event channel so the reader task can insert it
        // into dispatch.streams atomically with the StreamOpenOk resolution
        // avoiding a race where early StreamData frames are dropped.
        let (data_tx, data_rx) =
            mpsc::channel::<StreamEvent>(crate::client::STREAM_EVENT_QUEUE_CAP);
        {
            let mut d = self.dispatch.lock().await;
            // audit cycle-6 (P3 review): do NOT prune abandoned waiters here —
            // they hold FIFO position for their still-pending reply (the daemon
            // replies in request order; removing a middle slot would misalign
            // every later reply). Abandoned slots self-drain when their reply
            // arrives and is consumed-and-discarded (see the StreamOpenOk/Err
            // handlers in client.rs). They count transiently against the cap;
            // that is acceptable backpressure, not a correctness issue.
            if d.pending_stream_opens.len() >= crate::client::MAX_PENDING_OPS {
                return Err(ClientError::Protocol(
                    "too many pending stream opens".into(),
                ));
            }
            d.pending_stream_opens.push_back((tx, data_tx));
        }

        let payload = StreamOpenPayload {
            dst_node_id,
            app_id: dst_app_id,
            endpoint_id: dst_endpoint_id,
            initial_window,
        };
        self.writer
            .write_frame(LocalAppMsg::StreamOpen as u16, &payload.encode())
            .await?;

        // audit cycle-6 (P3): bound the wait. On timeout `rx` is dropped, which
        // closes the queued sender so the dispatcher's `pop_next_open_stream`
        // skips this abandoned slot when a (late) reply finally arrives.
        let stream_id = match tokio::time::timeout(crate::client::STREAM_OPEN_TIMEOUT, rx).await {
            Ok(Ok(inner)) => inner?,
            Ok(Err(_)) => return Err(ClientError::ConnectionClosed),
            Err(_) => {
                return Err(ClientError::Protocol(
                    "timeout waiting for stream open".into(),
                ));
            }
        };

        Ok(VeilStream::new(stream_id, self.writer.clone(), data_rx))
    }
}

impl Drop for AppHandle {
    fn drop(&mut self) {
        // `tokio::spawn` from `Drop` panics
        // when no Tokio runtime is in TLS — most common when the host
        // app drops the handle from a non-tokio context (sync FFI
        // shutdown, panic-handler cleanup). Guard the spawn behind
        // `Handle::try_current` so a missing runtime degrades to a
        // best-effort skip of the UNBIND notification (the daemon
        // still GCs the binding via its keepalive timeout) instead of
        // crashing the host process.
        if tokio::runtime::Handle::try_current().is_err() {
            return;
        }
        let dispatch = Arc::clone(&self.dispatch);
        let endpoint_id = self.endpoint_id;
        let writer = self.writer.clone();
        let app_id = self.app_id;
        tokio::spawn(async move {
            {
                let mut d = dispatch.lock().await;
                d.endpoints.remove(&endpoint_id);
                d.inbound_streams.remove(&endpoint_id); // audit L-18
            }
            let payload = AppUnbindPayload {
                app_id,
                endpoint_id,
            };
            let _ = writer
                .write_frame(LocalAppMsg::AppUnbind as u16, &payload.encode())
                .await;
        });
    }
}

/// Send-only half of an [`AppHandle`]. Returned by
/// [`AppHandle::into_split`] alongside an [`AppReceiver`].
///
/// All `send*` methods take `&self`, so the sender can be moved into
/// a tokio task and shared by clone (writer is a cheap mpsc-sender wrapper).
pub struct AppSender {
    app_id: [u8; 32],
    endpoint_id: u32,
    writer: SharedWriter,
    /// Held so the dispatch table is updated on drop (unbind path)
    /// matching the lifetime semantics of the original AppHandle.
    dispatch: Arc<Mutex<DispatchTable>>,
}

impl Drop for AppSender {
    fn drop(&mut self) {
        // same `Handle::try_current` guard as
        // `AppHandle::drop` — see that impl for the full rationale.
        if tokio::runtime::Handle::try_current().is_err() {
            return;
        }
        let dispatch = Arc::clone(&self.dispatch);
        let endpoint_id = self.endpoint_id;
        let writer = self.writer.clone();
        let app_id = self.app_id;
        tokio::spawn(async move {
            {
                let mut d = dispatch.lock().await;
                d.endpoints.remove(&endpoint_id);
                d.inbound_streams.remove(&endpoint_id); // audit L-18
            }
            let payload = AppUnbindPayload {
                app_id,
                endpoint_id,
            };
            let _ = writer
                .write_frame(LocalAppMsg::AppUnbind as u16, &payload.encode())
                .await;
        });
    }
}

impl AppSender {
    /// Returns this endpoint's numeric ID.
    pub fn endpoint_id(&self) -> u32 {
        self.endpoint_id
    }

    /// Returns this endpoint's 32-byte app ID assigned by the node.
    pub fn app_id(&self) -> &[u8; 32] {
        &self.app_id
    }

    /// Send a datagram (mirror [`AppHandle::send`]).
    pub async fn send(
        &self,
        dst_node_id: [u8; 32],
        dst_app_id: [u8; 32],
        dst_endpoint_id: u32,
        data: &[u8],
    ) -> Result<(), ClientError> {
        self.send_owned(dst_node_id, dst_app_id, dst_endpoint_id, data.to_vec())
            .await
    }

    /// Zero-copy variant of [`Self::send`] that takes ownership of `data`.
    /// Use when the caller already owns the buffer (e.g. an ogate TUN-read
    /// `Vec<u8>`) to skip the slice→Vec copy `send` performs internally.
    ///
    /// Hot path goes through `SharedWriter::write_app_ipc_send_owned`
    /// which builds the IPC frame в а single buffer — one allocation,
    /// one copy of `data`.  See its doc-comment для why this matters.
    pub async fn send_owned(
        &self,
        dst_node_id: [u8; 32],
        dst_app_id: [u8; 32],
        dst_endpoint_id: u32,
        data: Vec<u8>,
    ) -> Result<(), ClientError> {
        // Default flags = 0 (no ACK, not anonymous).  `send_owned` mirrors
        // the original `AppIpcSendPayload { require_ack: false, anonymous:
        // false, ... }` construction.
        self.writer
            .write_app_ipc_send_owned(
                &dst_node_id,
                &self.app_id,
                &dst_app_id,
                dst_endpoint_id,
                0,
                &data,
            )
            .await
    }

    /// Zero-DATA-copy send: caller supplies а `Vec<u8>` that already has
    /// [`crate::APP_IPC_SEND_PREFIX_BYTES`] uninit bytes reserved at the
    /// FRONT, then the datagram payload contiguous behind it.  SDK fills
    /// the prefix in place с FrameHeader + AppIpcSendPayload fixed fields
    /// и forwards the whole `buf` к the IPC writer task — no payload
    /// memcpy whatsoever.
    ///
    /// Used by ogate's solo-ship hot path where the TUN reader allocates
    /// the buffer with the prefix already reserved (see
    /// `Reader::read_packet_with_prefix`).
    pub async fn send_prepared(
        &self,
        dst_node_id: [u8; 32],
        dst_app_id: [u8; 32],
        dst_endpoint_id: u32,
        buf: Vec<u8>,
    ) -> Result<(), ClientError> {
        self.writer
            .send_prepared_app_ipc_send(
                buf,
                &dst_node_id,
                &self.app_id,
                &dst_app_id,
                dst_endpoint_id,
                0,
            )
            .await
    }

    /// Open a reliable byte-stream (mirror [`AppHandle::open_stream`]).
    ///
    /// making this available on `AppSender` so
    /// that FFI hosts that have already moved the receiver into a recv
    /// loop can still open new streams without losing the binding.
    pub async fn open_stream(
        &self,
        dst_node_id: [u8; 32],
        dst_app_id: [u8; 32],
        dst_endpoint_id: u32,
        initial_window: u32,
    ) -> Result<crate::stream::VeilStream, ClientError> {
        use tokio::sync::oneshot;

        let (tx, rx) = oneshot::channel::<Result<u32, ClientError>>();
        let (data_tx, data_rx) =
            mpsc::channel::<StreamEvent>(crate::client::STREAM_EVENT_QUEUE_CAP);
        {
            let mut d = self.dispatch.lock().await;
            // audit cycle-6 (P3 review): do NOT prune abandoned waiters — they
            // hold FIFO position for their pending reply (see AppHandle::open_stream
            // and the StreamOpenOk/Err handlers). They self-drain when consumed.
            if d.pending_stream_opens.len() >= crate::client::MAX_PENDING_OPS {
                return Err(ClientError::Protocol(
                    "too many pending stream opens".into(),
                ));
            }
            d.pending_stream_opens.push_back((tx, data_tx));
        }
        let payload = StreamOpenPayload {
            dst_node_id,
            app_id: dst_app_id,
            endpoint_id: dst_endpoint_id,
            initial_window,
        };
        self.writer
            .write_frame(LocalAppMsg::StreamOpen as u16, &payload.encode())
            .await?;
        // audit cycle-6 (P3): bound the wait (see AppHandle::open_stream).
        let stream_id = match tokio::time::timeout(crate::client::STREAM_OPEN_TIMEOUT, rx).await {
            Ok(Ok(inner)) => inner?,
            Ok(Err(_)) => return Err(ClientError::ConnectionClosed),
            Err(_) => {
                return Err(ClientError::Protocol(
                    "timeout waiting for stream open".into(),
                ));
            }
        };
        Ok(crate::stream::VeilStream::new(
            stream_id,
            self.writer.clone(),
            data_rx,
        ))
    }
}

/// Receive-only half of an [`AppHandle`]. Returned by
/// [`AppHandle::into_split`] alongside an [`AppSender`].
///
/// Carries both the datagram-rx и inbound-stream-rx halves so callers
/// что bound serving an inbound stream protocol (proxy server,
/// mailbox bridge) keep access к [`Self::accept_stream`] after the
/// split.
pub struct AppReceiver {
    rx: mpsc::Receiver<IncomingMessage>,
    inbound_streams_rx: mpsc::Receiver<IncomingStream>,
}

impl AppReceiver {
    /// Receive the next incoming datagram, or `None` if the IPC
    /// connection closed.
    pub async fn recv(&mut self) -> Result<Option<IncomingMessage>, ClientError> {
        Ok(self.rx.recv().await)
    }

    /// Wait для the next incoming stream opened by а remote peer.
    /// Audit batch 2026-05-25 phase M — mirror of
    /// [`AppHandle::accept_stream`].  Без this, the split-API consumer
    /// could not serve stream-based protocols (oproxy server, mailbox
    /// drain) on the receive side.
    pub async fn accept_stream(&mut self) -> Option<IncomingStream> {
        self.inbound_streams_rx.recv().await
    }
}
