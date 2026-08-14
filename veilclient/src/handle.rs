//! Per-endpoint application handle.

use std::sync::Arc;
use std::time::Duration;

use veilcore::proto::{
    AppIpcRtSendPayload, AppUnbindPayload, LocalAppMsg, SenderProvenance, StreamOpenPayload,
};

use crate::client::{DispatchTable, SharedWriter, StreamEvent};
use crate::error::ClientError;
use crate::stream::VeilStream;
use tokio::sync::{Mutex, mpsc};

/// A single incoming datagram delivered to this endpoint.
pub struct IncomingMessage {
    /// Node ID of the sender (32 bytes).
    ///
    /// A NAME, not yet an identity — read [`Self::provenance`] before treating
    /// it as one.
    pub src_node_id: [u8; 32],
    /// What the node knows about [`Self::src_node_id`] (X/V-01): the trust
    /// level the delivering path decided, carried on the IPC wire as the
    /// trailing byte of `AppDeliverPayload`. [`SenderProvenance::Claimed`]
    /// means nothing corroborates the name — the normal, correct level for the
    /// anonymous path, and never a basis for authorization.
    pub provenance: SenderProvenance,
    /// App ID of the sender on the originating node (32 bytes).
    pub src_app_id: [u8; 32],
    /// Raw payload bytes.
    pub data: Vec<u8>,
    /// Opaque reply handle: non-zero when this message arrived over the
    /// authenticated anonymous transport WITH a one-time reply block attached.
    /// Pass it to [`AppHandle::reply`] / [`AppSender::reply`] to answer without
    /// either side publishing a public rendezvous ad. `0` means "not
    /// repliable" (a plain send, or an authenticated send without a reply
    /// block). Single-use and TTL-bounded daemon-side (default 300 s).
    pub reply_id: u64,
}

/// A remote peer opened a byte-stream to this endpoint.  Returned by
/// [`AppHandle::accept_stream`] / [`AppReceiver::accept_stream`].
pub struct IncomingStream {
    /// Live byte-pipe — implements `AsyncRead` + `AsyncWrite`.
    pub stream: crate::stream::VeilStream,
    /// 32-byte node_id of the peer that initiated the stream.
    pub src_node_id: [u8; 32],
    /// What the node knows about [`Self::src_node_id`] (X/V-01) — same
    /// contract as [`IncomingMessage::provenance`]. Both of today's open paths
    /// authenticate the initiator, so this is normally
    /// [`SenderProvenance::SessionPeer`] or [`SenderProvenance::LocalIpc`];
    /// an allow-list check belongs on this field, not on `src_node_id` alone.
    pub provenance: SenderProvenance,
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
    /// from being built outside the daemon).  Populated by the
    /// reader-task dispatch when a remote peer opens a stream to
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

    /// Wait for the next incoming stream opened by a remote peer.
    ///
    /// Returns `None` when the IPC connection k the daemon closes.
    /// Each accepted stream carries its initiator's `src_node_id`
    /// — callers that want to enforce an allowlist (server-side proxy
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
    /// Returns `(AppSender, AppReceiver)`.  The unbind lease goes with the
    /// SENDER, and only the sender:
    ///
    /// * Dropping (or [closing](AppSender::close)) the **sender** releases the
    ///   binding — the endpoint leaves the local dispatch table and an
    ///   APP_UNBIND goes to the daemon — **even while the receiver is still
    ///   alive**. That receiver then simply stops being fed.
    /// * Dropping the **receiver** does nothing to the binding at all;
    ///   `AppReceiver` has no `Drop`. The endpoint stays bound and inbound
    ///   frames are dropped by the dispatcher for want of a queue.
    ///
    /// This doc used to say the binding lived until BOTH halves were dropped.
    /// It never did, and no caller depended on the difference: all seven
    /// production split sites hold the sender for at least as long as the
    /// receiver. Documented as it behaves rather than made to match, because
    /// the alternative (a shared lease released when the last half drops)
    /// would make the moment of unbinding depend on which task happened to
    /// finish last — nondeterministic teardown to fix a defect with zero
    /// callers.
    ///
    /// Audit batch 2026-05-25 phase M (cross-audit closure):
    /// `AppReceiver` carries both the datagram `rx` AND the inbound-
    /// stream `inbound_streams_rx`.  Pre-fix the split dropped
    /// `inbound_streams_rx` silently, leaving callers that had bound
    /// for server-side stream-accept (mailbox proxy, oproxy server,
    /// mesh bridge) without a way to dispatch on accept post-split.
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
            unbind_on_drop: true,
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

    /// Send a loss-tolerant datagram through the non-onion Delivery relay path
    /// at REALTIME priority, even if a direct session also exists.
    pub async fn send_relay_realtime_owned(
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
                veil_proto::ipc::IPC_SEND_FLAG_RELAY_REALTIME,
                &data,
            )
            .await
    }

    /// Relay call-control at REALTIME priority using the legacy-compatible
    /// `Delivery::Forward` wire shape (no optional traffic-class suffix).
    pub async fn send_relay_control_owned(
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
                veil_proto::ipc::IPC_SEND_FLAG_RELAY_CONTROL_COMPAT,
                &data,
            )
            .await
    }

    /// Send call media that was already sealed with an ephemeral E2E media
    /// key. The node preserves the compact ciphertext instead of adding a
    /// per-packet ML-KEM envelope; only the loss-tolerant relay path accepts
    /// this flag combination.
    pub async fn send_relay_media_sealed_owned(
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
                veil_proto::ipc::IPC_SEND_FLAG_RELAY_REALTIME
                    | veil_proto::ipc::IPC_SEND_FLAG_RELAY_MEDIA_SEALED,
                &data,
            )
            .await
    }

    /// Send `data` as an AUTHENTICATED anonymous message over the
    /// onion/rendezvous transport. Unlike a plain send, the onion hides the
    /// sender's network location from every relay while the recipient
    /// cryptographically verifies WHO sent it.
    ///
    /// v1 limitations: one-way (no reply channel); the recipient must have
    /// opted in to receiving (a resolvable RendezvousAd); fire-and-forget —
    /// `Ok` means the request was accepted and handed to the first hop, NOT
    /// delivery-confirmed (there is no end-to-end ACK). Large messages are
    /// fragmented automatically up to a fixed ceiling.
    pub async fn send_anonymous_authenticated(
        &self,
        dst_node_id: [u8; 32],
        dst_app_id: [u8; 32],
        dst_endpoint_id: u32,
        data: &[u8],
    ) -> Result<(), ClientError> {
        self.writer
            .write_app_ipc_send_owned(
                &dst_node_id,
                &self.app_id,
                &dst_app_id,
                dst_endpoint_id,
                veil_proto::ipc::IPC_SEND_FLAG_ANONYMOUS_AUTHENTICATED,
                data,
            )
            .await
    }

    /// Like [`Self::send_anonymous_authenticated`], but additionally attach a
    /// one-time reply block so the recipient can answer WITHOUT either side
    /// publishing a public rendezvous ad (no presence leak). The reply is
    /// delivered back to THIS endpoint (`self.app_id`, `reply_endpoint_id`);
    /// pass `self.endpoint_id()` for `reply_endpoint_id` to receive it here.
    /// The recipient gets a non-zero [`IncomingMessage::reply_id`].
    pub async fn send_anonymous_authenticated_with_reply(
        &self,
        dst_node_id: [u8; 32],
        dst_app_id: [u8; 32],
        dst_endpoint_id: u32,
        reply_endpoint_id: u32,
        data: &[u8],
    ) -> Result<(), ClientError> {
        use veil_proto::ipc::{IPC_SEND_FLAG_ANONYMOUS_AUTHENTICATED, IPC_SEND_FLAG_EXPECT_REPLY};
        self.writer
            .write_app_ipc_send_reply_aware(
                &dst_node_id,
                &self.app_id,
                &dst_app_id,
                dst_endpoint_id,
                IPC_SEND_FLAG_ANONYMOUS_AUTHENTICATED | IPC_SEND_FLAG_EXPECT_REPLY,
                0,
                reply_endpoint_id,
                data,
            )
            .await
    }

    /// Reply to a message received over the authenticated anonymous transport,
    /// addressing it by the opaque [`IncomingMessage::reply_id`] it carried. The
    /// daemon routes the reply back over the original sender's rendezvous path —
    /// no public ad on either side. `reply_id` is valid until its daemon-side TTL
    /// expires and may be used more than once (the daemon peeks the reply block,
    /// it does not consume it) — deduplicate at the app layer if needed; a
    /// stale/expired id returns [`ClientError`] (the daemon answers
    /// `REPLY_UNKNOWN`).
    pub async fn reply(&self, reply_id: u64, data: &[u8]) -> Result<(), ClientError> {
        self.writer
            .write_app_ipc_send_reply_aware(
                &[0u8; 32],
                &self.app_id,
                &[0u8; 32],
                0,
                veil_proto::ipc::IPC_SEND_FLAG_IS_REPLY,
                reply_id,
                0,
                data,
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
        let request_id = self.writer.alloc_request_id();
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
            d.pending_stream_opens
                .push_back((request_id, (tx, data_tx)));
        }

        let payload = StreamOpenPayload {
            dst_node_id,
            app_id: dst_app_id,
            endpoint_id: dst_endpoint_id,
            initial_window,
        };
        self.writer
            .write_request_frame(
                LocalAppMsg::StreamOpen as u16,
                request_id,
                &payload.encode(),
            )
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

impl AppHandle {
    /// Release the binding and wait for it, instead of hoping `Drop` can.
    ///
    /// `Drop` cannot await, so it spawns — and a spawn needs a Tokio runtime in
    /// TLS. Dropped from a sync FFI teardown or a panic handler there is none,
    /// so the local dispatch entry survived and `AppUnbind` never went out: the
    /// next bind of the same endpoint then landed on a stale registration and
    /// received nothing, until the daemon's keepalive eventually GC'd it (audit
    /// V-08). A caller that CAN await should say so rather than depend on where
    /// the value happens to be dropped.
    ///
    /// Idempotent: a later `Drop` finds the endpoint already gone and the
    /// second `AppUnbind` is a no-op on the daemon side.
    pub async fn close(&self) {
        {
            let mut d = self.dispatch.lock().await;
            d.endpoints.remove(&self.endpoint_id);
            d.inbound_streams.remove(&self.endpoint_id);
        }
        let payload = AppUnbindPayload {
            app_id: self.app_id,
            endpoint_id: self.endpoint_id,
        };
        let _ = self
            .writer
            .write_frame(LocalAppMsg::AppUnbind as u16, &payload.encode())
            .await;
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
            // Nothing further is possible here: the unbind must await and there
            // is no executor. The binding stays registered until the daemon's
            // keepalive reaps it, and a re-bind before then gets the stale
            // entry. Callers that can await should use [`AppHandle::close`]
            // (audit V-08) — this path is the fallback, not the contract.
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
    /// Explicit [close](Self::close) performs the unbind synchronously and
    /// clears this flag so Drop cannot enqueue a duplicate frame.
    unbind_on_drop: bool,
}

impl Drop for AppSender {
    fn drop(&mut self) {
        if !self.unbind_on_drop {
            return;
        }
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

/// Upper bound on how long [`AppSender::close`] may spend releasing an
/// endpoint.
///
/// `close` is on a UI-blocking path: `veil_app_close` calls it under
/// `runtime.block_on` from the host's FFI thread (Dart's isolate thread), and
/// the `NativeFinalizer` reaches it during GC. Both the dispatch-table lock
/// and the writer's bounded frame channel can stall unboundedly — a wedged
/// daemon that stops draining the socket backs the channel up and
/// `write_frame` parks forever — so an untimed close freezes the app in a
/// completely routine failure mode.
///
/// Degrading to best-effort is safe: an un-sent APP_UNBIND leaves the binding
/// registered until the daemon's keepalive reaps it, which is exactly the
/// fallback [`AppHandle::drop`] already relies on when there is no runtime to
/// spawn on. Two seconds is far above any healthy close (a channel `send` that
/// isn't backed up completes in microseconds) and far below a human noticing a
/// hang.
pub const APP_UNBIND_DEADLINE: Duration = Duration::from_secs(2);

impl AppSender {
    /// Reliably release this endpoint and its local dispatch slots.
    ///
    /// Unlike Drop, this works when the caller originated outside Tokio (the
    /// FFI close path): the caller enters a runtime and awaits the APP_UNBIND
    /// write instead of relying on a spawned best-effort cleanup task.
    ///
    /// Bounded by [`APP_UNBIND_DEADLINE`] — see there for why a close that
    /// cannot complete must degrade rather than block. Both awaited steps are
    /// cancel-safe: the dispatch mutex is a plain `tokio::sync::Mutex`, and the
    /// frame write is a single `mpsc::send` of one already-encoded buffer, so a
    /// cancelled close can never leave a half-written frame on the wire.
    pub async fn close(mut self) {
        self.unbind_on_drop = false;
        let payload = AppUnbindPayload {
            app_id: self.app_id,
            endpoint_id: self.endpoint_id,
        };
        let dispatch = Arc::clone(&self.dispatch);
        let writer = self.writer.clone();
        let endpoint_id = self.endpoint_id;
        let _ = tokio::time::timeout(APP_UNBIND_DEADLINE, async move {
            {
                let mut d = dispatch.lock().await;
                d.endpoints.remove(&endpoint_id);
                d.inbound_streams.remove(&endpoint_id);
            }
            let _ = writer
                .write_frame(LocalAppMsg::AppUnbind as u16, &payload.encode())
                .await;
        })
        .await;
    }

    /// Returns this endpoint's numeric ID.
    pub fn endpoint_id(&self) -> u32 {
        self.endpoint_id
    }

    /// Returns this endpoint's 32-byte app ID assigned by the node.
    pub fn app_id(&self) -> &[u8; 32] {
        &self.app_id
    }

    /// Send to the OTHER DEVICES of this identity.
    ///
    /// `my_node_id` is our own identity address, which is also what every
    /// device of it answers to — so the node cannot tell from the address
    /// whether we mean ourselves or our siblings, and a plain send addressed
    /// there is short-circuited into a local delivery that never leaves the
    /// machine. The flag says which of the two is meant.
    pub async fn send_to_my_devices_owned(
        &self,
        my_node_id: [u8; 32],
        dst_app_id: [u8; 32],
        dst_endpoint_id: u32,
        data: Vec<u8>,
    ) -> Result<(), ClientError> {
        self.writer
            .write_app_ipc_send_owned(
                &my_node_id,
                &self.app_id,
                &dst_app_id,
                dst_endpoint_id,
                veil_proto::ipc::IPC_SEND_FLAG_MY_OTHER_DEVICES,
                &data,
            )
            .await
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
    /// which builds the IPC frame in a single buffer — one allocation,
    /// one copy of `data`.  See its doc-comment for why this matters.
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

    /// Send a loss-tolerant datagram through the non-onion Delivery relay path
    /// at REALTIME priority, even if a direct session also exists.
    pub async fn send_relay_realtime_owned(
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
                veil_proto::ipc::IPC_SEND_FLAG_RELAY_REALTIME,
                &data,
            )
            .await
    }

    /// Split-handle variant of [`AppHandle::send_relay_control_owned`].
    pub async fn send_relay_control_owned(
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
                veil_proto::ipc::IPC_SEND_FLAG_RELAY_CONTROL_COMPAT,
                &data,
            )
            .await
    }

    /// Split-handle variant of [`AppHandle::send_relay_media_sealed_owned`].
    pub async fn send_relay_media_sealed_owned(
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
                veil_proto::ipc::IPC_SEND_FLAG_RELAY_REALTIME
                    | veil_proto::ipc::IPC_SEND_FLAG_RELAY_MEDIA_SEALED,
                &data,
            )
            .await
    }

    /// Send one loss-tolerant media datagram at REALTIME session priority.
    ///
    /// Mirrors [`AppHandle::send_rt_data`] for split handles used by native
    /// media pumps. Delivery is fire-and-forget and may be dropped when the
    /// direct session is absent or congested.
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

    /// Send an AUTHENTICATED anonymous message (mirror
    /// [`AppHandle::send_anonymous_authenticated`]). The onion hides the
    /// sender's location from relays; the recipient verifies the sender.
    /// Fire-and-forget (no end-to-end ACK); the recipient must have opted in
    /// to receiving.
    pub async fn send_anonymous_authenticated(
        &self,
        dst_node_id: [u8; 32],
        dst_app_id: [u8; 32],
        dst_endpoint_id: u32,
        data: &[u8],
    ) -> Result<(), ClientError> {
        self.writer
            .write_app_ipc_send_owned(
                &dst_node_id,
                &self.app_id,
                &dst_app_id,
                dst_endpoint_id,
                veil_proto::ipc::IPC_SEND_FLAG_ANONYMOUS_AUTHENTICATED,
                data,
            )
            .await
    }

    /// Authenticated anonymous send WITH an attached one-time reply block
    /// (mirror [`AppHandle::send_anonymous_authenticated_with_reply`]). The
    /// reply is delivered to `(self.app_id, reply_endpoint_id)`.
    pub async fn send_anonymous_authenticated_with_reply(
        &self,
        dst_node_id: [u8; 32],
        dst_app_id: [u8; 32],
        dst_endpoint_id: u32,
        reply_endpoint_id: u32,
        data: &[u8],
    ) -> Result<(), ClientError> {
        use veil_proto::ipc::{IPC_SEND_FLAG_ANONYMOUS_AUTHENTICATED, IPC_SEND_FLAG_EXPECT_REPLY};
        self.writer
            .write_app_ipc_send_reply_aware(
                &dst_node_id,
                &self.app_id,
                &dst_app_id,
                dst_endpoint_id,
                IPC_SEND_FLAG_ANONYMOUS_AUTHENTICATED | IPC_SEND_FLAG_EXPECT_REPLY,
                0,
                reply_endpoint_id,
                data,
            )
            .await
    }

    /// Like [`Self::send_anonymous_authenticated_with_reply`], but the caller
    /// GIVES the relay's KEM key (`dst_x25519_pk`) directly — so the daemon
    /// routes the source-routed onion STRAIGHT to `(dst_node_id, dst_x25519_pk)`
    /// with NO rendezvous-ad self-resolve (the flaky lookup that returned
    /// `NoRendezvous`). Still authenticated (the relay verifies us). The
    /// KEM-key-given mailbox FETCH and ACK. `dst_x25519_pk` is a PUBLIC key (the
    /// relay's published KEM key). Awaits the daemon's status ack (unlike the
    /// self-resolving variant, which is fire-and-forget).
    ///
    /// `reply_endpoint_id` non-zero attaches a one-time reply block delivered
    /// back to `(this app, reply_endpoint_id)`. Pass **0** when the target never
    /// answers: no block, and no ephemeral reply circuit built for it. Endpoint
    /// 0 receives nothing, so the two readings agree — a block addressed there
    /// would be undeliverable.
    #[allow(clippy::too_many_arguments)]
    pub async fn send_anonymous_authenticated_direct_with_reply(
        &self,
        dst_node_id: [u8; 32],
        dst_x25519_pk: [u8; 32],
        dst_app_id: [u8; 32],
        dst_endpoint_id: u32,
        reply_endpoint_id: u32,
        data: &[u8],
    ) -> Result<(), ClientError> {
        use crate::client::{MAX_PENDING_OPS, prune_closed};
        // hop_count is advisory on the wire — the daemon routes at its configured
        // default circuit length (same hop the self-resolving authenticated send
        // uses). Carried for SendAnonymousDirect wire symmetry; we pass 0 so the
        // daemon's default governs.
        let (tx, rx) = tokio::sync::oneshot::channel();
        let request_id = self.writer.alloc_request_id();
        {
            let mut d = self.dispatch.lock().await;
            prune_closed(&mut d.pending_send_authenticated_direct_with_reply);
            if d.pending_send_authenticated_direct_with_reply.len() >= MAX_PENDING_OPS {
                return Err(ClientError::Protocol(format!(
                    "send_anonymous_authenticated_direct_with_reply queue at cap \
                     ({MAX_PENDING_OPS}); daemon may be hung"
                )));
            }
            d.pending_send_authenticated_direct_with_reply
                .push_back((request_id, tx));
        }
        let payload = veilcore::proto::SendAuthenticatedDirectWithReplyPayload {
            target_node_id: dst_node_id,
            target_x25519_pk: dst_x25519_pk,
            target_app_id: dst_app_id,
            src_app_id: self.app_id,
            target_endpoint_id: dst_endpoint_id,
            reply_endpoint_id,
            hop_count: 0,
            data: data.to_vec(),
        };
        self.writer
            .write_request_frame(
                LocalAppMsg::SendAuthenticatedDirectWithReply as u16,
                request_id,
                &payload.encode(),
            )
            .await?;
        match tokio::time::timeout(std::time::Duration::from_secs(10), rx).await {
            Ok(Ok(0)) => Ok(()),
            Ok(Ok(code)) => Err(ClientError::Protocol(format!(
                "send_anonymous_authenticated_direct_with_reply rejected by daemon \
                 (status {code})"
            ))),
            Ok(Err(_)) => Err(ClientError::Protocol("daemon dropped reply".into())),
            Err(_) => Err(ClientError::Protocol(
                "timeout waiting for SendAuthenticatedDirectWithReplyResult".into(),
            )),
        }
    }

    /// Reply by opaque `reply_id` (mirror [`AppHandle::reply`]). Routes back
    /// over the original sender's rendezvous path; no public ad either side.
    pub async fn reply(&self, reply_id: u64, data: &[u8]) -> Result<(), ClientError> {
        self.writer
            .write_app_ipc_send_reply_aware(
                &[0u8; 32],
                &self.app_id,
                &[0u8; 32],
                0,
                veil_proto::ipc::IPC_SEND_FLAG_IS_REPLY,
                reply_id,
                0,
                data,
            )
            .await
    }

    /// Zero-DATA-copy send: caller supplies a `Vec<u8>` that already has
    /// [`crate::APP_IPC_SEND_PREFIX_BYTES`] uninit bytes reserved at the
    /// FRONT, then the datagram payload contiguous behind it.  SDK fills
    /// the prefix in place with FrameHeader + AppIpcSendPayload fixed fields
    /// and forwards the whole `buf` to the IPC writer task — no payload
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
        let request_id = self.writer.alloc_request_id();
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
            d.pending_stream_opens
                .push_back((request_id, (tx, data_tx)));
        }
        let payload = StreamOpenPayload {
            dst_node_id,
            app_id: dst_app_id,
            endpoint_id: dst_endpoint_id,
            initial_window,
        };
        self.writer
            .write_request_frame(
                LocalAppMsg::StreamOpen as u16,
                request_id,
                &payload.encode(),
            )
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
/// Carries both the datagram-rx and inbound-stream-rx halves so callers
/// that bound serving an inbound stream protocol (proxy server,
/// mailbox bridge) keep access to [`Self::accept_stream`] after the
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

    /// Wait for the next incoming stream opened by a remote peer.
    /// Audit batch 2026-05-25 phase M — mirror of
    /// [`AppHandle::accept_stream`].  Without this, the split-API consumer
    /// could not serve stream-based protocols (oproxy server, mailbox
    /// drain) on the receive side.
    pub async fn accept_stream(&mut self) -> Option<IncomingStream> {
        self.inbound_streams_rx.recv().await
    }

    /// Split into the raw datagram + inbound-stream channels so a host (e.g.
    /// the C FFI) can drain each on an independent task. `select!`-ing
    /// [`recv`](Self::recv) and [`accept_stream`](Self::accept_stream) on the
    /// same `&mut self` is a borrow conflict; owning the two channels
    /// separately resolves it. Both channels remain bound to the original
    /// endpoint until dropped.
    pub fn into_parts(
        self,
    ) -> (
        mpsc::Receiver<IncomingMessage>,
        mpsc::Receiver<IncomingStream>,
    ) {
        (self.rx, self.inbound_streams_rx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{DispatchTable, SharedWriter};

    /// Build an `AppSender` whose IPC frame channel is ALREADY FULL and whose
    /// receiver is never drained — the shape a wedged daemon presents, and the
    /// one that made an untimed `close` park forever.
    fn sender_on_a_wedged_writer() -> (AppSender, mpsc::Receiver<Vec<u8>>) {
        let (tx, rx) = mpsc::channel::<Vec<u8>>(1);
        tx.try_send(vec![0u8; 4]).expect("prime the single slot");
        (
            AppSender {
                app_id: [7u8; 32],
                endpoint_id: 9,
                writer: SharedWriter::new(tx),
                dispatch: Arc::new(Mutex::new(DispatchTable::new())),
                unbind_on_drop: true,
            },
            rx,
        )
    }

    /// `AppSender::close` is on a UI-blocking path: `veil_app_close` drives it
    /// under `runtime.block_on` from the host's FFI thread, and the Dart
    /// `NativeFinalizer` reaches it during GC. It must therefore never
    /// out-wait its own deadline, no matter what the daemon is doing.
    ///
    /// Time is paused, so the deadline elapses instantly in wall-clock; the
    /// OUTER timeout is the failure detector — without an inner deadline
    /// `close` never completes and the outer one fires instead of hanging the
    /// suite.
    #[tokio::test(start_paused = true)]
    async fn close_degrades_to_best_effort_on_a_wedged_writer() {
        let (sender, _rx_never_drained) = sender_on_a_wedged_writer();
        let started = tokio::time::Instant::now();
        let outcome = tokio::time::timeout(APP_UNBIND_DEADLINE * 4, sender.close()).await;
        assert!(
            outcome.is_ok(),
            "close outlived 4x its own deadline against a wedged writer — the \
             host UI thread is blocked on this call"
        );
        assert!(
            started.elapsed() <= APP_UNBIND_DEADLINE * 2,
            "close should give up at its deadline, took {:?}",
            started.elapsed()
        );
    }

    /// CONTROL for the above: with a writer that CAN accept the frame, close
    /// completes on its own — so the green result there is the deadline
    /// firing, not `close` short-circuiting for some unrelated reason. Also
    /// pins that the unbind is still actually emitted on the healthy path.
    #[tokio::test(start_paused = true)]
    async fn close_emits_the_unbind_when_the_writer_is_healthy() {
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(4);
        let sender = AppSender {
            app_id: [7u8; 32],
            endpoint_id: 9,
            writer: SharedWriter::new(tx),
            dispatch: Arc::new(Mutex::new(DispatchTable::new())),
            unbind_on_drop: true,
        };
        let started = tokio::time::Instant::now();
        sender.close().await;
        assert!(
            started.elapsed() < APP_UNBIND_DEADLINE,
            "a healthy close must not wait on the deadline at all"
        );
        let frame = rx.try_recv().expect("APP_UNBIND frame must be queued");
        assert!(!frame.is_empty());
    }

    /// Build a bound `AppHandle` over a live dispatch table, ready to split.
    async fn bound_handle_async() -> (
        Arc<Mutex<DispatchTable>>,
        AppHandle,
        mpsc::Receiver<Vec<u8>>,
    ) {
        let (tx, rx) = mpsc::channel::<Vec<u8>>(8);
        let dispatch = Arc::new(Mutex::new(DispatchTable::new()));
        let (mtx, mrx) = mpsc::channel::<IncomingMessage>(1);
        let (stx, srx) = mpsc::channel::<IncomingStream>(1);
        {
            let mut d = dispatch.lock().await;
            d.endpoints.insert(9, mtx);
            d.inbound_streams.insert(9, stx);
        }
        let handle = AppHandle::new(
            [7u8; 32],
            9,
            SharedWriter::new(tx),
            Arc::clone(&dispatch),
            mrx,
            srx,
        );
        (dispatch, handle, rx)
    }

    /// `into_split`'s doc claimed the binding lived until BOTH halves were
    /// dropped. The unbind lease belongs to the SENDER alone: dropping it
    /// releases the endpoint even while the receiver is alive. Pins the real
    /// behaviour so the doc and the code cannot drift apart again.
    #[tokio::test]
    async fn dropping_the_sender_unbinds_while_the_receiver_is_still_alive() {
        let (dispatch, handle, mut wire) = bound_handle_async().await;
        let (sender, receiver) = handle.into_split();

        drop(sender);
        // `AppSender::drop` does its cleanup on a spawned task.
        let mut released = false;
        for _ in 0..1000 {
            if !dispatch.lock().await.endpoints.contains_key(&9) {
                released = true;
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(
            released,
            "dropping the sender must release the endpoint even though the \
             receiver half is still held"
        );
        assert!(
            wire.try_recv().is_ok(),
            "an APP_UNBIND must have been queued for the daemon"
        );
        // Held across the assertions on purpose: the receiver's liveness is
        // exactly what the old doc claimed would keep the binding.
        drop(receiver);
    }

    /// The other half of the same correction: `AppReceiver` has no `Drop`, so
    /// dropping it alone changes nothing about the binding.
    #[tokio::test]
    async fn dropping_the_receiver_alone_leaves_the_binding_untouched() {
        let (dispatch, handle, mut wire) = bound_handle_async().await;
        let (sender, receiver) = handle.into_split();

        drop(receiver);
        for _ in 0..100 {
            tokio::task::yield_now().await;
        }
        assert!(
            dispatch.lock().await.endpoints.contains_key(&9),
            "dropping the receiver must NOT unbind"
        );
        assert!(
            wire.try_recv().is_err(),
            "dropping the receiver must not emit an APP_UNBIND"
        );
        // And the sender still works against the live binding.
        sender
            .send([1u8; 32], [2u8; 32], 3, b"still bound")
            .await
            .expect("send on a still-bound endpoint");
        assert!(wire.try_recv().is_ok(), "the datagram reached the writer");
        drop(sender);
    }

    /// The endpoint must leave the local dispatch table on close even when the
    /// wire write is the part that gets abandoned — otherwise a rebind of the
    /// same endpoint_id on this connection would still collide.
    #[tokio::test(start_paused = true)]
    async fn close_clears_local_dispatch_even_when_the_write_is_abandoned() {
        let (sender, _rx_never_drained) = sender_on_a_wedged_writer();
        let dispatch = Arc::clone(&sender.dispatch);
        let endpoint_id = sender.endpoint_id;
        {
            let (etx, _erx) = mpsc::channel::<IncomingMessage>(1);
            dispatch.lock().await.endpoints.insert(endpoint_id, etx);
        }
        let _ = tokio::time::timeout(APP_UNBIND_DEADLINE * 4, sender.close()).await;
        assert!(
            !dispatch.lock().await.endpoints.contains_key(&endpoint_id),
            "a close that abandoned the wire write still owes the local table \
             its cleanup"
        );
    }
}
