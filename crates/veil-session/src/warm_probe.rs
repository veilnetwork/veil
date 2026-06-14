//! Warm-probe task).
//!
//! Per-session background task that maintains a **second** transport-layer
//! connection to the same peer, using a scheme from
//! [`cfg::HotStandbyConfig::alt_scheme_order`] that differs from the primary.
//! No OVL1 bytes are exchanged on the warm socket until a handoff is
//! triggered — the socket only holds a live TCP (and if applicable TLS)
//! connection, kept alive by kernel-level TCP keepalive.
//!
//! When the controller, or an operator admin command
//! via stage (b)/B5) asks for a swap, the probe runs the handoff
//! protocol (audit cycle-6 T1 added the warm-socket challenge-response):
//!
//! ```text
//! (1) primary: self → peer SessionMsg::HandoffInit { nonce }
//! (2) primary: peer → self SessionMsg::HandoffAck { nonce } (via HandoffAckWaiters)
//! (3) warm:    self → peer SessionMsg::HandoffAttach { session_id }   (bare announce)
//! (4) warm:    peer → self SessionMsg::HandoffChallenge { fresh }
//! (5) warm:    self → peer SessionMsg::HandoffResponse { hmac(tx_key, session_id || fresh) }
//! (6) push warm stream into local SessionSwapRegistry → our runner swaps
//! ```
//!
//! The per-socket challenge in (4) is what defeats replay: a captured (3)+(5)
//! replayed on a fresh socket gets a DIFFERENT challenge, so the captured (5)
//! no longer verifies and an attacker cannot mint a new one without `tx_key`.
//!
//! Step (4) mirrors what [`super::super::runtime::handoff::peek_and_dispatch`]
//! does on the peer's accept-side: both ends deliver the new byte pipe
//! into the corresponding runner's `swap_rx`, so both `SessionRunner`s
//! switch to the warm transport at the same logical moment (bounded by
//! the `tokio::select!` granularity in each main loop).

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};

use crate::SessionTxRegistry;
use crate::handoff::{HandoffAckWaiters, SessionSwapRegistry};
use veil_cfg::{HotStandbyConfig, NodeId};
use veil_proto::{
    codec::{decode_header, encode_header},
    family::{FrameFamily, SessionMsg},
    header::FrameHeader,
    session::{
        HandoffAttachPayload, HandoffChallengePayload, HandoffInitPayload, HandoffResponsePayload,
    },
};
use veil_transport::{BoxIoStream, TransportContext, TransportRegistry, TransportUri};

/// Handle returned by [`spawn_warm_probe`] for the controller to send
/// commands to the probe task.
#[derive(Clone)]
pub struct WarmProbeHandle {
    cmd_tx: mpsc::Sender<WarmProbeCommand>,
}

impl WarmProbeHandle {
    /// Ask the probe to run the handoff protocol now. Returns a receiver
    /// that resolves with the outcome when the probe either completes the
    /// handoff (Ok) or bails (Err). After this the probe exits — a single
    /// `WarmProbeHandle` is one-shot by design; a fresh probe would have
    /// to be spawned if a second handoff were ever needed on the same
    /// session.
    pub async fn initiate_handoff(&self) -> Result<(), WarmProbeError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(WarmProbeCommand::InitiateHandoff(tx))
            .await
            .map_err(|_| WarmProbeError::ProbeGone)?;
        rx.await.map_err(|_| WarmProbeError::ProbeGone)?
    }

    // Note: there is intentionally no `shutdown` method. The probe
    // task exits naturally when the last `WarmProbeHandle` is dropped
    // (the cmd_rx channel returns `None`). An earlier draft shipped
    // an explicit `Shutdown` command; it had no callers and was
    // removed — the drop-based exit is sufficient and avoids the
    // dual-path "did you call shutdown OR drop?" footgun.
}

/// Errors surfaced by the probe to its caller.
#[derive(Debug, thiserror::Error)]
pub enum WarmProbeError {
    #[error("probe task has exited")]
    ProbeGone,
    #[error("warm-probe dial failed: {0}")]
    Dial(String),
    #[error("HandoffInit send failed (no session_tx_registry entry for peer)")]
    PrimarySendFailed,
    #[error("HandoffAck timed out after {0:?}")]
    AckTimeout(Duration),
    #[error("HandoffAttach write failed: {0}")]
    AttachWrite(String),
    #[error("no active runner swap_tx for session_id — session already closed")]
    RunnerGone,
}

pub enum WarmProbeCommand {
    InitiateHandoff(oneshot::Sender<Result<(), WarmProbeError>>),
}

/// Input needed to dial and drive a warm-probe task. Each field is an
/// `Arc`/plain-data handle the probe borrows for the duration of the
/// session — nothing here is owned uniquely.
pub struct WarmProbeConfig {
    /// This session's `session_id` (from the OVL1 handshake). Used as
    /// the lookup key in the handoff + swap registries and embedded in
    /// the `HandoffAttach` payload.
    pub session_id: [u8; 32],
    /// Peer's `node_id` — addresses the HandoffInit frame to the right
    /// outbox entry in `SessionTxRegistry`.
    pub peer_id: NodeId,
    /// This session's AEAD TX key (== peer's RX key under OVL1 DH).
    /// Keys the HMAC that proves to the peer that this warm socket
    /// belongs to a legitimate session owner.
    pub tx_key: [u8; 32],
    /// Pre-parsed alt transport URI (e.g. `tls://peer.example:9906`).
    /// The probe dials this at spawn time.
    pub alt_uri: TransportUri,
    pub transport_registry: Arc<TransportRegistry>,
    pub transport_ctx: Arc<TransportContext>,
    pub session_tx_registry: Arc<std::sync::RwLock<SessionTxRegistry>>,
    pub handoff_ack_waiters: Arc<HandoffAckWaiters>,
    pub swap_registry: Arc<SessionSwapRegistry>,
    pub hot_standby: HotStandbyConfig,
}

/// Spawn the warm-probe task for one session. Returns a handle the
/// controller uses to ask for a handoff. The task dials the alt
/// transport at startup; a dial failure is surfaced through the handle's
/// first `initiate_handoff` call rather than panicking the spawn.
pub fn spawn_warm_probe(cfg: WarmProbeConfig) -> WarmProbeHandle {
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<WarmProbeCommand>(4);
    tokio::spawn(async move {
        // dial the alt transport. Store the result (Err) so
        // the first InitiateHandoff call can surface the dial failure.
        let dial_result: Result<BoxIoStream, String> = {
            let registry = Arc::clone(&cfg.transport_registry);
            let ctx = Arc::clone(&cfg.transport_ctx);
            match registry.connect(&cfg.alt_uri, ctx).await {
                Ok(conn) => conn.into_stream().map_err(|e| e.to_string()),
                Err(e) => Err(e.to_string()),
            }
        };

        let (mut warm_stream, dial_err): (Option<BoxIoStream>, Option<String>) = match dial_result {
            Ok(s) => (Some(s), None),
            Err(e) => (None, Some(e)),
        };

        // One-shot lifecycle — we wait for exactly ONE command, act on
        // it, and exit. Any later commands queued on `cmd_rx` are
        // implicitly dropped when we return. A fresh probe can be
        // spawned if another handoff attempt is needed later.
        match cmd_rx.recv().await {
            None => {} // handle dropped — clean exit
            Some(WarmProbeCommand::InitiateHandoff(reply)) => {
                let result = if let Some(msg) = &dial_err {
                    Err(WarmProbeError::Dial(msg.clone()))
                } else if let Some(stream) = warm_stream.take() {
                    drive_handoff(&cfg, stream).await
                } else {
                    Err(WarmProbeError::Dial("warm stream absent".to_owned()))
                };
                let _ = reply.send(result);
            }
        }
    });
    WarmProbeHandle { cmd_tx }
}

/// The actual handoff choreography, separated so it's test-friendly.
async fn drive_handoff(
    cfg: &WarmProbeConfig,
    mut warm_stream: BoxIoStream,
) -> Result<(), WarmProbeError> {
    // (1) Generate a fresh nonce. `OsRng` so the HMAC input is not
    // attacker-predictable.
    use rand_core::{OsRng, RngCore};
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);

    // Register ack waiter BEFORE sending HandoffInit so the receiver
    // can never race ahead of our registration.
    let (ack_tx, mut ack_rx) = mpsc::channel::<[u8; 32]>(1);
    let _ack_guard = cfg.handoff_ack_waiters.register(cfg.session_id, ack_tx);

    // (2) Build + send HandoffInit over primary session.
    let init_body = HandoffInitPayload { nonce }.encode();
    let mut init_hdr = FrameHeader::new(FrameFamily::Session as u8, SessionMsg::HandoffInit as u16);
    init_hdr.body_len = init_body.len() as u32;
    let mut init_frame = encode_header(&init_hdr).to_vec();
    init_frame.extend_from_slice(&init_body);
    {
        let reg = cfg
            .session_tx_registry
            .read()
            .unwrap_or_else(|p| p.into_inner());
        if !reg.send_to(
            cfg.peer_id.as_bytes(),
            veil_proto::priority::INTERACTIVE,
            init_frame,
        ) {
            return Err(WarmProbeError::PrimarySendFailed);
        }
    }

    // (3) Wait for peer's HandoffAck — with timeout.
    let ack_timeout = Duration::from_secs(cfg.hot_standby.handoff_timeout_secs);
    let peer_nonce = match tokio::time::timeout(ack_timeout, ack_rx.recv()).await {
        Ok(Some(n)) => n,
        Ok(None) => return Err(WarmProbeError::ProbeGone), // sender dropped
        Err(_) => return Err(WarmProbeError::AckTimeout(ack_timeout)),
    };
    // Paranoia: the waiter map is keyed by session_id, so the nonce we
    // pull must be the one WE put in HandoffInit (the runner forwards
    // whatever arrived on HandoffAck, but a conforming peer echoes
    // verbatim). Reject any mismatch defensively.
    if peer_nonce != nonce {
        return Err(WarmProbeError::AckTimeout(ack_timeout));
    }

    // (4) audit cycle-6 (T1): challenge-response on the warm socket.
    // (4a) Send a BARE HandoffAttach announce (session_id only). The HMAC is no
    // longer carried here — the receiver replies with a fresh per-socket
    // challenge, which we answer in (4c). This is what makes a replayed attach
    // useless (the replay gets a different challenge it cannot answer).
    let attach = HandoffAttachPayload {
        session_id: cfg.session_id,
    };
    let attach_body = attach.encode();
    let mut attach_hdr =
        FrameHeader::new(FrameFamily::Session as u8, SessionMsg::HandoffAttach as u16);
    attach_hdr.body_len = attach_body.len() as u32;
    let mut attach_frame = encode_header(&attach_hdr).to_vec();
    attach_frame.extend_from_slice(&attach_body);
    warm_stream
        .write_all(&attach_frame)
        .await
        .map_err(|e| WarmProbeError::AttachWrite(e.to_string()))?;

    // (4b) Read the receiver's HandoffChallenge (header + body), bounded by the
    // same handoff timeout as the ack wait.
    let chal_deadline = Duration::from_secs(cfg.hot_standby.handoff_timeout_secs);
    let challenge = read_handoff_challenge(&mut warm_stream, chal_deadline).await?;

    // (4c) Answer with HandoffResponse: HMAC over (session_id || challenge)
    // keyed by our tx_key. Only the legitimate session owner can compute this.
    let resp_hmac = HandoffAttachPayload::compute_hmac(&cfg.tx_key, &cfg.session_id, &challenge);
    let resp_body = HandoffResponsePayload { hmac: resp_hmac }.encode();
    let mut resp_hdr = FrameHeader::new(
        FrameFamily::Session as u8,
        SessionMsg::HandoffResponse as u16,
    );
    resp_hdr.body_len = resp_body.len() as u32;
    let mut resp_frame = encode_header(&resp_hdr).to_vec();
    resp_frame.extend_from_slice(&resp_body);
    warm_stream
        .write_all(&resp_frame)
        .await
        .map_err(|e| WarmProbeError::AttachWrite(e.to_string()))?;

    // (5) Push the warm stream into our own runner's swap_rx. The
    // runner's `await_next_input` picks it up and sets `self.stream =
    // new_stream` at the next tick — preserving AEAD state, session_id
    // and all session-level counters.
    let swap_tx = cfg
        .swap_registry
        .get(&cfg.session_id)
        .ok_or(WarmProbeError::RunnerGone)?;
    swap_tx
        .send(warm_stream)
        .await
        .map_err(|_| WarmProbeError::RunnerGone)?;
    Ok(())
}

/// audit cycle-6 (T1): read a `HandoffChallenge` frame (header + 32-byte body)
/// from the warm socket, bounded by `deadline`. Returns the challenge bytes.
async fn read_handoff_challenge(
    stream: &mut BoxIoStream,
    deadline: Duration,
) -> Result<[u8; 32], WarmProbeError> {
    const HEADER_SIZE: usize = veil_proto::header::HEADER_SIZE;
    let mut hdr_buf = [0u8; HEADER_SIZE];
    match tokio::time::timeout(deadline, stream.read_exact(&mut hdr_buf)).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            return Err(WarmProbeError::AttachWrite(format!(
                "challenge header: {e}"
            )));
        }
        Err(_) => return Err(WarmProbeError::AckTimeout(deadline)),
    }
    let hdr = decode_header(&hdr_buf)
        .map_err(|e| WarmProbeError::AttachWrite(format!("bad challenge header: {e}")))?;
    if hdr.family != FrameFamily::Session as u8
        || hdr.msg_type != SessionMsg::HandoffChallenge as u16
        || hdr.body_len as usize != HandoffChallengePayload::WIRE_SIZE
    {
        return Err(WarmProbeError::AttachWrite(
            "unexpected frame where HandoffChallenge expected".to_owned(),
        ));
    }
    let mut body = vec![0u8; hdr.body_len as usize];
    match tokio::time::timeout(deadline, stream.read_exact(&mut body)).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => return Err(WarmProbeError::AttachWrite(format!("challenge body: {e}"))),
        Err(_) => return Err(WarmProbeError::AckTimeout(deadline)),
    }
    let chal = HandoffChallengePayload::decode(&body)
        .map_err(|e| WarmProbeError::AttachWrite(format!("bad challenge: {e}")))?;
    Ok(chal.challenge)
}

#[cfg(test)]
mod tests {
    use super::*;
    use veil_transport::BoxIoStream;

    /// Verify `initiate_handoff` surfaces a dial failure cleanly rather
    /// than wedging the caller. We feed an unreachable URI to a fresh
    /// TransportRegistry + TransportContext (the default registry has
    /// TCP wired, so `tcp://127.0.0.1:1` typically errors on refused
    /// connection).
    #[tokio::test(flavor = "current_thread")]
    async fn dial_failure_surfaces_as_dial_error() {
        use veil_cfg::HotStandbyConfig;

        let registry = Arc::new(TransportRegistry::with_defaults());
        let ctx = Arc::new(TransportContext::for_debug().expect("debug ctx"));
        let bad_uri = TransportUri::parse("tcp://127.0.0.1:1").unwrap();

        let session_tx_registry = Arc::new(std::sync::RwLock::new(SessionTxRegistry::new()));
        let handoff_ack_waiters = Arc::new(HandoffAckWaiters::new());
        let swap_registry = Arc::new(SessionSwapRegistry::new());

        let cfg = WarmProbeConfig {
            session_id: [0x11u8; 32],
            peer_id: NodeId::from([0x22u8; 32]),
            tx_key: [0x33u8; 32],
            alt_uri: bad_uri,
            transport_registry: registry,
            transport_ctx: ctx,
            session_tx_registry,
            handoff_ack_waiters,
            swap_registry,
            hot_standby: HotStandbyConfig::default(),
        };
        let handle = spawn_warm_probe(cfg);

        let res = handle.initiate_handoff().await;
        assert!(
            matches!(res, Err(WarmProbeError::Dial(_))),
            "expected Dial error, got {res:?}"
        );
    }

    /// Happy path: stage the primary-side registry to accept the
    /// HandoffInit send, stage a peer that delivers a valid HandoffAck
    /// via the waiters map, stage a swap_rx that receives the stream
    /// after HandoffAttach is written. Verify end-to-end: probe writes
    /// HandoffInit correctly + produces HandoffAttach with correct HMAC
    /// + pushes stream into swap_rx.
    #[tokio::test(flavor = "current_thread")]
    async fn handoff_happy_path_drives_full_protocol() {
        use tokio::io::AsyncReadExt as _;
        use veil_cfg::HotStandbyConfig;
        use veil_proto::codec::decode_header;

        let registry = Arc::new(TransportRegistry::with_defaults());
        let ctx = Arc::new(TransportContext::for_debug().expect("debug ctx"));

        // Stand up a real TCP listener on an ephemeral port so `dial` has
        // someone to connect to; the listener's accepted socket is what
        // we read HandoffAttach from.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let alt_uri = TransportUri::parse(&format!("tcp://{listen_addr}")).unwrap();

        let session_id = [0xAAu8; 32];
        let peer_id: NodeId = [0xBBu8; 32].into();
        let tx_key = [0xCCu8; 32];

        // Register the peer in SessionTxRegistry so send_to can route
        // HandoffInit somewhere. We consume the outgoing frame from
        // this rx to verify it's a valid HandoffInit.
        let session_tx_registry = Arc::new(std::sync::RwLock::new(SessionTxRegistry::new()));
        let mut peer_outbox_rx = session_tx_registry.write().unwrap().register(peer_id);

        let handoff_ack_waiters = Arc::new(HandoffAckWaiters::new());
        let swap_registry = Arc::new(SessionSwapRegistry::new());
        // Install the runner's end of the swap channel so drive_handoff
        // has somewhere to push the warm stream after HandoffAttach.
        let (runner_swap_tx, mut runner_swap_rx) = mpsc::channel::<BoxIoStream>(1);
        let _swap_guard = swap_registry.register(session_id, peer_id, runner_swap_tx, tx_key);

        let cfg = WarmProbeConfig {
            session_id,
            peer_id,
            tx_key,
            alt_uri,
            transport_registry: registry,
            transport_ctx: ctx,
            session_tx_registry: Arc::clone(&session_tx_registry),
            handoff_ack_waiters: Arc::clone(&handoff_ack_waiters),
            swap_registry: Arc::clone(&swap_registry),
            hot_standby: HotStandbyConfig::default(),
        };
        let handle = spawn_warm_probe(cfg);

        // Accept the warm probe's TCP connection on the fixture side.
        // The probe dials IMMEDIATELY on spawn so accept fires soon.
        let (mut warm_server_side, _peer_addr) = listener.accept().await.unwrap();

        // Probe is now armed. Fire the handoff in the background — it
        // will block on the ack waiter until we deliver one.
        let probe_done = tokio::spawn({
            let handle = handle.clone();
            async move { handle.initiate_handoff().await }
        });

        // Consume HandoffInit from the primary-side outbox.
        let (_prio, init_frame) =
            tokio::time::timeout(Duration::from_secs(2), peer_outbox_rx.recv())
                .await
                .expect("HandoffInit not sent within 2s")
                .unwrap();
        let init_hdr = decode_header(&init_frame[..veil_proto::header::HEADER_SIZE]).unwrap();
        assert_eq!(init_hdr.family, FrameFamily::Session as u8);
        assert_eq!(init_hdr.msg_type, SessionMsg::HandoffInit as u16);
        let init_body = HandoffInitPayload::decode(&init_frame[veil_proto::header::HEADER_SIZE..])
            .expect("HandoffInit body decodes");

        // Simulate the peer's HandoffAck: deliver the same nonce via
        // the waiters map (that's exactly what the runner's dispatcher
        // does on real incoming HandoffAck).
        let ack_sender = handoff_ack_waiters
            .get(&session_id)
            .expect("probe must have registered ack waiter before HandoffInit");
        ack_sender.send(init_body.nonce).await.unwrap();

        // audit cycle-6 (T1): read the bare HandoffAttach announce from the warm
        // socket, then drive the challenge-response as the receiver would.
        let mut attach_hdr_buf = [0u8; veil_proto::header::HEADER_SIZE];
        tokio::time::timeout(
            Duration::from_secs(2),
            warm_server_side.read_exact(&mut attach_hdr_buf),
        )
        .await
        .expect("HandoffAttach header timeout")
        .unwrap();
        let attach_hdr = decode_header(&attach_hdr_buf).unwrap();
        assert_eq!(attach_hdr.family, FrameFamily::Session as u8);
        assert_eq!(attach_hdr.msg_type, SessionMsg::HandoffAttach as u16);
        let mut attach_body_buf = [0u8; HandoffAttachPayload::WIRE_SIZE];
        warm_server_side
            .read_exact(&mut attach_body_buf)
            .await
            .unwrap();
        let attach = HandoffAttachPayload::decode(&attach_body_buf).unwrap();
        assert_eq!(attach.session_id, session_id);

        // Receiver sends a fresh challenge; the probe must answer with the
        // tx_key-keyed HMAC over (session_id || challenge).
        let challenge = [0xC1u8; 32];
        {
            let chal_body = HandoffChallengePayload { challenge }.encode();
            let mut chal_hdr = FrameHeader::new(
                FrameFamily::Session as u8,
                SessionMsg::HandoffChallenge as u16,
            );
            chal_hdr.body_len = chal_body.len() as u32;
            let mut chal_frame = encode_header(&chal_hdr).to_vec();
            chal_frame.extend_from_slice(&chal_body);
            warm_server_side.write_all(&chal_frame).await.unwrap();
        }
        // Read HandoffResponse and verify the HMAC.
        let mut resp_hdr_buf = [0u8; veil_proto::header::HEADER_SIZE];
        tokio::time::timeout(
            Duration::from_secs(2),
            warm_server_side.read_exact(&mut resp_hdr_buf),
        )
        .await
        .expect("HandoffResponse header timeout")
        .unwrap();
        let resp_hdr = decode_header(&resp_hdr_buf).unwrap();
        assert_eq!(resp_hdr.msg_type, SessionMsg::HandoffResponse as u16);
        let mut resp_body_buf = [0u8; HandoffResponsePayload::WIRE_SIZE];
        warm_server_side
            .read_exact(&mut resp_body_buf)
            .await
            .unwrap();
        let response = HandoffResponsePayload::decode(&resp_body_buf).unwrap();
        assert_eq!(
            response.hmac,
            HandoffAttachPayload::compute_hmac(&tx_key, &session_id, &challenge),
            "response HMAC must be keyed with tx_key and cover (session_id || challenge)",
        );

        // The probe must have delivered the warm stream to the runner's
        // swap_rx as the final step.
        let _stream = tokio::time::timeout(Duration::from_secs(2), runner_swap_rx.recv())
            .await
            .expect("probe did not push warm stream")
            .expect("channel closed");

        // Probe task reports success.
        let outcome = tokio::time::timeout(Duration::from_secs(2), probe_done)
            .await
            .expect("probe task hung")
            .unwrap();
        assert!(outcome.is_ok(), "probe: {outcome:?}");
    }

    /// Without a matching entry in SessionTxRegistry, `send_to` returns
    /// false and the probe surfaces `PrimarySendFailed`.
    #[tokio::test(flavor = "current_thread")]
    async fn handoff_without_primary_outbox_errors_cleanly() {
        use veil_cfg::HotStandbyConfig;

        let registry = Arc::new(TransportRegistry::with_defaults());
        let ctx = Arc::new(TransportContext::for_debug().expect("debug ctx"));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let alt_uri =
            TransportUri::parse(&format!("tcp://{}", listener.local_addr().unwrap())).unwrap();

        // Empty registry — peer_id has no entry.
        let session_tx_registry = Arc::new(std::sync::RwLock::new(SessionTxRegistry::new()));
        let handoff_ack_waiters = Arc::new(HandoffAckWaiters::new());
        let swap_registry = Arc::new(SessionSwapRegistry::new());

        let cfg = WarmProbeConfig {
            session_id: [1u8; 32],
            peer_id: NodeId::from([2u8; 32]),
            tx_key: [3u8; 32],
            alt_uri,
            transport_registry: registry,
            transport_ctx: ctx,
            session_tx_registry,
            handoff_ack_waiters,
            swap_registry,
            hot_standby: HotStandbyConfig::default(),
        };
        let handle = spawn_warm_probe(cfg);

        // Accept + immediately drop so dial succeeds.
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let res = handle.initiate_handoff().await;
        assert!(
            matches!(res, Err(WarmProbeError::PrimarySendFailed)),
            "expected PrimarySendFailed, got {res:?}"
        );
    }

    /// No HandoffAck ever delivered → probe times out on the configured
    /// `handoff_timeout_secs` and reports `AckTimeout`. Uses a very short
    /// (1s) real timeout instead of `tokio::time::advance` so we don't need
    /// the `test-util` tokio feature.
    #[tokio::test(flavor = "current_thread")]
    async fn handoff_ack_timeout_surfaces_correctly() {
        let registry = Arc::new(TransportRegistry::with_defaults());
        let ctx = Arc::new(TransportContext::for_debug().expect("debug ctx"));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let alt_uri =
            TransportUri::parse(&format!("tcp://{}", listener.local_addr().unwrap())).unwrap();

        let peer_id: NodeId = [0xEEu8; 32].into();
        let session_tx_registry = Arc::new(std::sync::RwLock::new(SessionTxRegistry::new()));
        let _outbox_rx = session_tx_registry.write().unwrap().register(peer_id);
        let handoff_ack_waiters = Arc::new(HandoffAckWaiters::new());
        let swap_registry = Arc::new(SessionSwapRegistry::new());

        let hs = HotStandbyConfig {
            handoff_timeout_secs: 1,
            ..HotStandbyConfig::default()
        };

        let cfg = WarmProbeConfig {
            session_id: [9u8; 32],
            peer_id,
            tx_key: [8u8; 32],
            alt_uri,
            transport_registry: registry,
            transport_ctx: ctx,
            session_tx_registry,
            handoff_ack_waiters,
            swap_registry,
            hot_standby: hs,
        };
        let handle = spawn_warm_probe(cfg);
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let res = handle.initiate_handoff().await;
        assert!(
            matches!(res, Err(WarmProbeError::AckTimeout(_))),
            "expected AckTimeout, got {res:?}"
        );
    }
}
