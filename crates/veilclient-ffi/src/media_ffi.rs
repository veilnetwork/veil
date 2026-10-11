//! The call-media entry points: opening a channel, feeding it, closing it.
//!
//! The machinery lives in [`crate::media`] — the sealed cell, the wire format,
//! the recv registry. This is the surface a host calls: open a channel over
//! whichever of the three transports applies (anonymous onion, direct P2P
//! datagram, ordinary relay), push datagrams at it, read its stats, repair it,
//! close it.
//!
//! Splitting the surface from the machinery is the boundary that was already
//! there implicitly: `media.rs` never had a single `extern "C"` function, and
//! these never had a line of cell-format logic. They simply both lived in the
//! wrong place — the machinery in its own file and the twelve calls that use
//! it a thousand lines deep in `lib.rs`.
//!
//! `veil_debug_set_rt_trace` and `veil_debug_set_publish_pause` sat in the
//! middle of this run and did NOT come along: they are debug knobs for the
//! whole node, not part of the media plane, and the only thing they shared
//! with it was an address in the file.
//!
//! Moved verbatim out of `lib.rs` (report24 RUNTIME-3), declared `pub mod` so
//! cbindgen still exports every declaration; the generated header is reordered
//! by the move and the ABI contract hash moves with it. Nothing is added or
//! removed.

// Every item here is `node-embedded`-only, so the import is too — the same
// lesson `ratchet.rs` taught: a glob names whatever happens to be there, so
// the default-feature build never has to agree with the all-features one.
#[cfg(feature = "node-embedded")]
use super::*;

#[cfg(feature = "node-embedded")]
pub mod path_probe_ffi;

#[cfg(feature = "node-embedded")]
mod ingress_diagnostics;
#[cfg(feature = "node-embedded")]
use ingress_diagnostics::{Reason as IngressRefusal, refuse as refuse_ingress};

#[cfg(feature = "node-embedded")]
fn media_is_vp8_rtp(payload: &[u8]) -> bool {
    if payload.len() < 2 || (payload[0] >> 6) != 2 {
        return false;
    }
    // rtcp-mux RTCP packet types occupy the 64..=95 range. Video RTP is the
    // fixed VP8 payload type configured by veil_media_engine.cc.
    (payload[1] & 0x7f) == 96
}

#[cfg(feature = "node-embedded")]
fn media_is_rtcp(mut packet: &[u8]) -> bool {
    if packet.is_empty() {
        return false;
    }
    while !packet.is_empty() {
        if packet.len() < 4 || packet[0] >> 6 != 2 || !(192..=223).contains(&packet[1]) {
            return false;
        }
        let len = 4 * (usize::from(u16::from_be_bytes([packet[2], packet[3]])) + 1);
        if len > packet.len() {
            return false;
        }
        if packet[0] & 0x20 != 0 {
            let padding = usize::from(packet[len - 1]);
            if len != packet.len() || padding == 0 || padding > len - 4 {
                return false;
            }
        }
        packet = &packet[len..];
    }
    true
}

// Local scheduling classification. This is computed before sealing and is
// sent only to our IPC daemon; no audio/video class is added to relay frames.
#[cfg(feature = "node-embedded")]
fn media_cell_is_video(cell: &[u8]) -> bool {
    if cell.first() != Some(&media::MEDIA_BATCH_MAGIC) {
        return media_is_vp8_rtp(cell);
    }
    let Some(len_bytes) = cell.get(3..5) else {
        return false;
    };
    let len = u16::from_be_bytes([len_bytes[0], len_bytes[1]]) as usize;
    cell.get(5..5usize.saturating_add(len))
        .is_some_and(media_is_vp8_rtp)
}

#[cfg(feature = "node-embedded")]
fn media_cell_plane(cell: &[u8]) -> media::LocalMediaPlane {
    if media_cell_is_video(cell) {
        media::LocalMediaPlane::Secondary
    } else {
        media::LocalMediaPlane::Primary
    }
}

// Endpoint freshness, not a wire TTL or a relay scheduling class. Do not
// replay queued RTP/RTCP after local route construction or IPC stalls.
#[cfg(feature = "node-embedded")]
const MEDIA_LOCAL_QUEUE_AGE: std::time::Duration = std::time::Duration::from_millis(200);

#[cfg(feature = "node-embedded")]
#[derive(Debug)]
struct QueuedMediaPacket {
    payload: Vec<u8>,
    deadline: tokio::time::Instant,
}

#[cfg(feature = "node-embedded")]
impl From<Vec<u8>> for QueuedMediaPacket {
    fn from(payload: Vec<u8>) -> Self {
        Self {
            payload,
            deadline: tokio::time::Instant::now() + MEDIA_LOCAL_QUEUE_AGE,
        }
    }
}

#[cfg(feature = "node-embedded")]
impl QueuedMediaPacket {
    fn expired(&self) -> bool {
        tokio::time::Instant::now() >= self.deadline
    }
}

/// Fold only packets already ready in this producer's queue. Overflow is kept
/// for the next cell; the other producer is never drained into this epoch.
#[cfg(feature = "node-embedded")]
fn media_ready_batch(
    first: QueuedMediaPacket,
    rx: &mut mpsc::Receiver<QueuedMediaPacket>,
    max_body: usize,
) -> (Option<QueuedMediaPacket>, Option<QueuedMediaPacket>) {
    if first.expired() {
        return (None, None);
    }
    let mut deadline = first.deadline;
    let mut body_len = 2 + 2 + first.payload.len();
    let mut packets = vec![first.payload];
    let mut pending = None;
    while packets.len() < 12 {
        let Ok(packet) = rx.try_recv() else {
            break;
        };
        if packet.expired() {
            continue;
        }
        let next_len = body_len.saturating_add(2 + packet.payload.len());
        if next_len > max_body {
            pending = Some(packet);
            break;
        }
        deadline = deadline.min(packet.deadline);
        body_len = next_len;
        packets.push(packet.payload);
    }
    (
        media::media_cell(packets, max_body).map(|payload| QueuedMediaPacket { payload, deadline }),
        pending,
    )
}

/// One anonymous producer per task: a blocked send or route repair cannot
/// hold the other producer's queue. Video warms lazily on its first packet.
#[cfg(feature = "node-embedded")]
async fn drain_anonymous_media<S, SF, W, WF>(
    mut rx: mpsc::Receiver<QueuedMediaPacket>,
    mut repair_rx: mpsc::Receiver<()>,
    cipher: Arc<media::MediaCipher>,
    plane: media::LocalMediaPlane,
    mut send: S,
    mut warm: W,
) where
    S: FnMut(media::SealedMediaCell) -> SF,
    SF: std::future::Future<Output = bool>,
    W: FnMut() -> WF,
    WF: std::future::Future<Output = ()>,
{
    let mut active = matches!(plane, media::LocalMediaPlane::Primary);
    if active {
        warm().await;
    }
    let mut consecutive_drops = 0u32;
    let mut pending = None;
    loop {
        let first = if let Some(packet) = pending.take() {
            packet
        } else {
            tokio::select! {
                biased;
                Some(()) = repair_rx.recv() => {
                    if active {
                        warm().await;
                    }
                    continue;
                }
                packet = rx.recv() => match packet {
                    Some(packet) => packet,
                    None => break,
                },
                else => break,
            }
        };
        if !active {
            active = true;
            warm().await;
        }
        let (cell, overflow) =
            media_ready_batch(first, &mut rx, anon_stream::media_batch_body_max());
        pending = overflow;
        let Some(cell) = cell else {
            continue;
        };
        let Some(sealed) = cipher.seal_on_plane(plane, &cell.payload) else {
            continue;
        };
        let sealed = sealed.with_local_deadline(cell.deadline);
        drop(cell);
        if sealed.locally_expired() {
            continue;
        }
        if send(sealed).await {
            consecutive_drops = 0;
        } else {
            consecutive_drops = consecutive_drops.saturating_add(1);
            // Re-resolve absent/stale ads in the background instead of keeping
            // an entire call on a black-holed route. Only this pool is repaired.
            if consecutive_drops % 20 == 1 {
                warm().await;
            }
        }
    }
}

#[cfg(all(test, feature = "node-embedded"))]
mod media_priority_tests;

#[cfg(all(test, feature = "node-embedded", feature = "test-low-difficulty"))]
mod media_route_network_tests;

/// The secondary sender is a local IPC handle, never a network flow label.
/// Cloning it before an await keeps the routing lock out of either pump.
#[cfg(feature = "node-embedded")]
struct MediaSenderSlot<T>(std::sync::RwLock<Arc<TokioMutex<Option<T>>>>);

#[cfg(feature = "node-embedded")]
impl<T> MediaSenderSlot<T> {
    fn new(sender: Arc<TokioMutex<Option<T>>>) -> Self {
        Self(std::sync::RwLock::new(sender))
    }
    fn current(&self) -> Arc<TokioMutex<Option<T>>> {
        Arc::clone(&self.0.read().unwrap_or_else(|p| p.into_inner()))
    }
    fn replace(&self, sender: Arc<TokioMutex<Option<T>>>) {
        *self.0.write().unwrap_or_else(|p| p.into_inner()) = sender;
    }
}

#[cfg(feature = "node-embedded")]
struct MediaOutboundCell {
    sealed: media::SealedMediaCell,
    marker: u8,
    payload_type: u32,
}

/// Shared mechanics, independent instances: neither pump waits for the other.
/// Each producer also owns its cipher epoch and synchronous seal lock.
#[cfg(feature = "node-embedded")]
async fn drain_media_packets<F, Fut>(
    rx: mpsc::Receiver<QueuedMediaPacket>,
    batching: Arc<std::sync::atomic::AtomicU8>,
    cipher: Arc<media::MediaCipher>,
    relay: bool,
    send: F,
) where
    F: FnMut(MediaOutboundCell) -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    drain_media_packets_on_plane(rx, batching, cipher, relay, None, send).await;
}

#[cfg(feature = "node-embedded")]
async fn drain_media_packets_on_plane<F, Fut>(
    mut rx: mpsc::Receiver<QueuedMediaPacket>,
    batching: Arc<std::sync::atomic::AtomicU8>,
    cipher: Arc<media::MediaCipher>,
    relay: bool,
    local_plane: Option<media::LocalMediaPlane>,
    mut send: F,
) where
    F: FnMut(MediaOutboundCell) -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    while let Some(first) = rx.recv().await {
        if first.expired() {
            continue;
        }
        let mut burst = vec![first];
        while burst.len() < MEDIA_TX_BURST_MAX {
            let Ok(packet) = rx.try_recv() else {
                break;
            };
            if !packet.expired() {
                burst.push(packet);
            }
        }
        let mode = batching.load(std::sync::atomic::Ordering::Relaxed);
        let (max_body, max_packets) = if relay && mode != MEDIA_BATCHING_OFF {
            (
                if mode == MEDIA_BATCHING_COMPACT_RELAY {
                    COMPACT_RELAY_MEDIA_CELL_MAX - 1
                } else {
                    7168
                },
                6,
            )
        } else {
            (RELAY_VIDEO_BATCH_BODY_MAX, RELAY_VIDEO_BATCH_MAX_PACKETS)
        };
        let cells = timed_media_cells(burst, mode != MEDIA_BATCHING_OFF, max_body, max_packets);
        for queued in cells {
            if queued.expired() {
                continue;
            }
            let packet = queued.payload;
            let (marker, payload_type) = if packet.len() >= 2 && packet[0] >> 6 == 2 {
                ((packet[1] >> 7) & 1, u32::from(packet[1] & 0x7f))
            } else {
                (0, 0)
            };
            let Some(sealed) = cipher.seal_on_plane(
                local_plane.unwrap_or_else(|| media_cell_plane(&packet)),
                &packet,
            ) else {
                continue;
            };
            let sealed = sealed.with_local_deadline(queued.deadline);
            drop(packet);
            if !send(MediaOutboundCell {
                sealed,
                marker,
                payload_type,
            })
            .await
            {
                return;
            }
        }
    }
}

#[cfg(feature = "node-embedded")]
async fn drain_relay_video<F, Fut>(
    rx: mpsc::Receiver<RelayVideoFrame>,
    batching: Arc<std::sync::atomic::AtomicU8>,
    cipher: Arc<media::MediaCipher>,
    stats: Arc<RelayMediaStats>,
    send: F,
) where
    F: FnMut(media::SealedMediaCell) -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    drain_relay_video_on_plane(
        rx,
        batching,
        cipher,
        stats,
        media::LocalMediaPlane::Secondary,
        send,
    )
    .await;
}

#[cfg(feature = "node-embedded")]
async fn drain_relay_video_on_plane<F, Fut>(
    mut rx: mpsc::Receiver<RelayVideoFrame>,
    batching: Arc<std::sync::atomic::AtomicU8>,
    cipher: Arc<media::MediaCipher>,
    stats: Arc<RelayMediaStats>,
    plane: media::LocalMediaPlane,
    mut send: F,
) where
    F: FnMut(media::SealedMediaCell) -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    while let Some(frame) = rx.recv().await {
        stats.start_frame(frame.enqueued_at.elapsed());
        let started = std::time::Instant::now();
        let legacy = batching.load(std::sync::atomic::Ordering::Relaxed) == MEDIA_BATCHING_LEGACY;
        let deadline = tokio::time::Instant::from_std(frame.enqueued_at) + MEDIA_LOCAL_QUEUE_AGE;
        let packets = frame
            .packets
            .into_iter()
            .map(|payload| QueuedMediaPacket { payload, deadline })
            .collect();
        for queued in timed_media_cells(
            packets,
            legacy,
            RELAY_VIDEO_BATCH_BODY_MAX,
            RELAY_VIDEO_BATCH_MAX_PACKETS,
        ) {
            if queued.expired() {
                continue;
            }
            let cell = queued.payload;
            let Some(sealed) = cipher.seal_on_plane(plane, &cell) else {
                continue;
            };
            let sealed = sealed.with_local_deadline(queued.deadline);
            drop(cell);
            if !send(sealed).await {
                return;
            }
        }
        stats.observe_frame_ipc(started.elapsed());
    }
}

/// Copy the two 32-byte directional call-media keys out of caller memory and
/// build the channel's cipher from them.
///
/// Every media channel takes these at OPEN, as required arguments with no
/// default. There used to be a separate `veil_media_channel_set_e2e_keys`, it
/// accepted only relay channels, and the host called it only when call
/// signalling claimed the peer spoke a new enough protocol — so "no keys" was
/// both a reachable state and a state an attacker could steer the host into by
/// editing an unauthenticated signal. Taking the keys here deletes that state:
/// a channel that cannot be keyed is a channel that never opens, and there is
/// nothing left to downgrade to.
///
/// Key material is copied immediately into zeroizing native state; the caller
/// may erase/free its buffers as soon as this returns.
#[cfg(feature = "node-embedded")]
unsafe fn media_cipher_from_keys(
    peer: &[u8; 32],
    tx_key: *const u8,
    rx_key: *const u8,
    err_out: *mut *mut c_char,
) -> Option<Arc<media::MediaCipher>> {
    use zeroize::Zeroize;
    let mut tx = [0u8; 32];
    let mut rx = [0u8; 32];
    unsafe {
        ptr::copy_nonoverlapping(tx_key, tx.as_mut_ptr(), tx.len());
        ptr::copy_nonoverlapping(rx_key, rx.as_mut_ptr(), rx.len());
    }
    let cipher = media::MediaCipher::new(peer, &tx, &rx).map(Arc::new);
    tx.zeroize();
    rx.zeroize();
    if cipher.is_none() {
        unsafe { write_err(err_out, "media keys must be two distinct non-zero keys") };
    }
    cipher
}

/// Open a lossy MEDIA datagram channel to `peer` over the anonymous circuit
/// (reuses the reliable stream's rendezvous/pool and warms the circuit in the
/// background). Per-packet RTP/RTCP then flows native↔native via
/// [`veil_media_send_datagram`] / [`veil_media_set_recv_callback`], sealed
/// end-to-end with `tx_key`/`rx_key`: two distinct, non-zero 32-byte
/// directional call-media keys, required, copied into zeroizing native state
/// (the caller may wipe its buffers as soon as this returns). Returns an
/// opaque channel id (> 0), or 0 on error.
#[cfg(feature = "node-embedded")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_media_open_channel(
    handle: *mut VeilHandle,
    peer_node_id: *const u8,
    tx_key: *const u8,
    rx_key: *const u8,
    err_out: *mut *mut c_char,
) -> u64 {
    if unsafe { guard::ffi_prelude(err_out, "veil_media_open_channel") }.is_err() {
        return 0;
    }
    null_check_with_default!(err_out, 0u64,
        "handle" => handle,
        "peer_node_id" => peer_node_id,
        "tx_key" => tx_key,
        "rx_key" => rx_key,
    );
    get_or_return!(
        handle_live,
        handle_table(),
        handle,
        err_out,
        0u64,
        "VeilHandle"
    );
    let mut peer = [0u8; 32];
    unsafe {
        ptr::copy_nonoverlapping(peer_node_id, peer.as_mut_ptr(), 32);
    }
    let Some(cipher) = (unsafe { media_cipher_from_keys(&peer, tx_key, rx_key, err_out) }) else {
        return 0;
    };
    let hub = match ensure_anon_hub(&handle_live.bundle, &handle_live.anon_hub) {
        Ok(h) => h,
        Err(e) => {
            unsafe { write_err(err_out, format!("media open: {e}")) };
            return 0;
        }
    };
    let id = MEDIA_NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let routes = hub.private_media_routes(peer, id, Arc::clone(&cipher));
    if let Some(routes) = &routes {
        routes.start(handle_live.bundle.runtime.handle());
    }
    let (tx_hi, rx_hi) = mpsc::channel::<QueuedMediaPacket>(MEDIA_TX_HI_QUEUE);
    let (tx_video, rx_video) = mpsc::channel::<QueuedMediaPacket>(MEDIA_TX_VIDEO_QUEUE);
    let (tx_screen, rx_screen) = mpsc::channel::<QueuedMediaPacket>(MEDIA_TX_VIDEO_QUEUE);
    let (repair_hi_tx, repair_hi_rx) = mpsc::channel::<()>(1);
    let (repair_video_tx, repair_video_rx) = mpsc::channel::<()>(1);
    let (repair_screen_tx, repair_screen_rx) = mpsc::channel::<()>(1);
    let spawn_producer = |rx, repair_rx, plane| {
        let send_hub = Arc::clone(&hub);
        let warm_hub = Arc::clone(&hub);
        let send_routes = routes.clone();
        let warm_routes = routes.clone();
        handle_live.bundle.runtime.spawn(drain_anonymous_media(
            rx,
            repair_rx,
            Arc::clone(&cipher),
            plane,
            move |sealed| {
                let hub = Arc::clone(&send_hub);
                let routes = send_routes.clone();
                async move {
                    if let Some(routes) = routes {
                        routes.send(plane, &sealed).await
                    } else {
                        hub.media_send_datagram(peer, plane, &sealed).await
                    }
                }
            },
            move || {
                let hub = Arc::clone(&warm_hub);
                let routes = warm_routes.clone();
                async move {
                    if let Some(routes) = routes {
                        routes.warm(plane).await
                    } else {
                        hub.media_open_channel(peer, plane).await
                    }
                }
            },
        ))
    };
    let task = spawn_producer(rx_hi, repair_hi_rx, media::LocalMediaPlane::Primary);
    let video_task = spawn_producer(rx_video, repair_video_rx, media::LocalMediaPlane::Secondary);
    let screen_task = spawn_producer(rx_screen, repair_screen_rx, media::LocalMediaPlane::Screen);
    MEDIA_CHANNELS
        .write()
        .unwrap_or_else(|p| p.into_inner())
        .insert(
            id,
            MediaChannel {
                path_probe: None,
                ingress: MediaIngress::with_screen(
                    tx_hi,
                    MediaVideoIngress::Packets(tx_video),
                    MediaVideoIngress::Packets(tx_screen),
                ),
                repair_tx: Some([repair_hi_tx, repair_video_tx, repair_screen_tx]),
                peer,
                task,
                video_task: Some(video_task),
                screen_task: Some(screen_task),
                video_sender: None,
                screen_sender: None,
                sender_app_id: None,
                batching: None,
                cipher,
                relay_stats: None,
                routes,
            },
        );
    id
}

/// Open a lossy MEDIA datagram channel to `peer` over a direct app endpoint.
/// Outbound RTP/RTCP is sealed with the required `tx_key`/`rx_key` (see
/// [`veil_media_open_channel`]) and sent from `app` to `(peer_node_id,
/// peer_app_id, peer_endpoint_id)`. Inbound direct media datagrams must be
/// received by the host on the same app endpoint and fed to
/// [`veil_media_dispatch_direct_datagram`].
///
/// The session under a "direct" channel is encrypted hop-to-hop to whatever
/// node terminates it, which is not the same thing as end-to-end, so this path
/// seals exactly like the other two.
#[cfg(feature = "node-embedded")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_media_open_direct_channel(
    app: *mut VeilApp,
    peer_node_id: *const u8,
    peer_app_id: *const u8,
    peer_endpoint_id: u32,
    tx_key: *const u8,
    rx_key: *const u8,
    err_out: *mut *mut c_char,
) -> u64 {
    if unsafe { guard::ffi_prelude(err_out, "veil_media_open_direct_channel") }.is_err() {
        return 0;
    }
    null_check_with_default!(err_out, 0u64,
        "app" => app,
        "peer_node_id" => peer_node_id,
        "peer_app_id" => peer_app_id,
        "tx_key" => tx_key,
        "rx_key" => rx_key,
    );
    get_or_return!(app_ref, app_table(), app, err_out, 0u64, "VeilApp");
    let mut peer = [0u8; 32];
    let mut peer_app = [0u8; 32];
    unsafe {
        ptr::copy_nonoverlapping(peer_node_id, peer.as_mut_ptr(), 32);
        ptr::copy_nonoverlapping(peer_app_id, peer_app.as_mut_ptr(), 32);
    }
    let Some(cipher) = (unsafe { media_cipher_from_keys(&peer, tx_key, rx_key, err_out) }) else {
        return 0;
    };

    // Opening an AppSender does not prove that the embedded node currently has
    // a direct session to the peer. REALTIME frames intentionally have no
    // relay fallback, so accepting a "direct" channel without this check would
    // create a valid-looking black hole until the session happened to appear.
    // Fail the open instead; the host must preserve the negotiated route and
    // surface/retry the direct failure rather than silently selecting onion.
    // The shared client mutex can itself be occupied by a slow control RPC
    // (join/discovery/call signalling), and the daemon's per-connection query
    // rate limiter drops PnetStatusQuery SILENTLY when its bucket is empty —
    // both stalls look identical to a single fixed-deadline probe. Probe in
    // short attempts inside one overall deadline: an attempt that times out is
    // retried (a dropped query gets a fresh token; a busy mutex gets another
    // chance), while an authoritative not-admitted reply fails fast. The
    // overall budget must stay inside the call FSM's media-start timeout so
    // the caller can still reach its relay fallback.
    enum ProbeVerdict {
        Admitted,
        NotAdmitted,
        TimedOut,
        RpcError,
    }
    let verdict = app_ref.bundle.runtime.block_on(async {
        const OVERALL: std::time::Duration = std::time::Duration::from_millis(2000);
        const ATTEMPT: std::time::Duration = std::time::Duration::from_millis(650);
        let started = std::time::Instant::now();
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            let att_start = std::time::Instant::now();
            let outcome = tokio::time::timeout(ATTEMPT, async {
                let lock_start = std::time::Instant::now();
                let client = app_ref.bundle.client.lock().await;
                let lock_ms = lock_start.elapsed().as_millis();
                (lock_ms, client.peer_pnet_status(&peer).await)
            })
            .await;
            match outcome {
                Ok((lock_ms, Ok(status))) => {
                    media::diag(format_args!(
                        "open_direct probe attempt={attempt} lock_ms={lock_ms} \
                         admitted={} in {}ms",
                        status.admitted,
                        att_start.elapsed().as_millis(),
                    ));
                    return if status.admitted {
                        ProbeVerdict::Admitted
                    } else {
                        ProbeVerdict::NotAdmitted
                    };
                }
                Ok((lock_ms, Err(e))) => {
                    media::diag(format_args!(
                        "open_direct probe attempt={attempt} lock_ms={lock_ms} rpc error: {e}"
                    ));
                    if started.elapsed() + ATTEMPT > OVERALL {
                        return ProbeVerdict::RpcError;
                    }
                    // An instant transport error would otherwise hot-spin the
                    // remaining budget away; give the connection a beat.
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
                Err(_) => {
                    media::diag(format_args!(
                        "open_direct probe attempt={attempt} timed out after {}ms \
                         (lock or rpc stalled)",
                        att_start.elapsed().as_millis(),
                    ));
                    if started.elapsed() + ATTEMPT > OVERALL {
                        return ProbeVerdict::TimedOut;
                    }
                }
            }
        }
    });
    match verdict {
        ProbeVerdict::Admitted => {}
        ProbeVerdict::NotAdmitted => {
            unsafe { write_err(err_out, "direct media session is not active") };
            return 0;
        }
        ProbeVerdict::TimedOut => {
            unsafe { write_err(err_out, "direct session probe timed out") };
            return 0;
        }
        ProbeVerdict::RpcError => {
            unsafe { write_err(err_out, "direct session probe failed") };
            return 0;
        }
    }

    let (tx_hi, rx_hi) = mpsc::channel::<QueuedMediaPacket>(MEDIA_TX_HI_QUEUE);
    let (tx_video, rx_video) = mpsc::channel::<QueuedMediaPacket>(MEDIA_TX_VIDEO_QUEUE);
    let (tx_screen, rx_screen) = mpsc::channel::<QueuedMediaPacket>(MEDIA_TX_VIDEO_QUEUE);
    let sender = Arc::clone(&app_ref.sender);
    let video_sender = Arc::new(MediaSenderSlot::new(Arc::clone(&sender)));
    let screen_sender = Arc::new(MediaSenderSlot::new(Arc::clone(&sender)));
    let batching = Arc::new(std::sync::atomic::AtomicU8::new(MEDIA_BATCHING_OFF));
    let started = std::time::Instant::now();
    let transport_seq = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let seq_high = Arc::clone(&transport_seq);
    let task = app_ref.bundle.runtime.spawn(drain_media_packets(
        rx_hi,
        Arc::clone(&batching),
        Arc::clone(&cipher),
        false,
        move |cell| {
            let sender = Arc::clone(&sender);
            let seq = Arc::clone(&seq_high);
            async move {
                let Some(guard) = cell.sealed.lock_while_fresh(&sender).await else {
                    return true;
                };
                let Some(sender) = guard.as_ref() else {
                    return false;
                };
                media::trace_sealed_cell("direct_send", &peer, cell.sealed.as_bytes());
                let timestamp_us = started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
                let _ = sender
                    .send_rt_data_on_local_lane_before(
                        veil_proto::priority::REALTIME,
                        peer,
                        peer_app,
                        peer_endpoint_id,
                        seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
                        timestamp_us,
                        cell.marker,
                        cell.payload_type,
                        cell.sealed.as_bytes(),
                        cell.sealed
                            .local_deadline()
                            .expect("native pump retains packet deadline"),
                    )
                    .await;
                true
            }
        },
    ));
    let video_source = Arc::clone(&video_sender);
    let seq_video = Arc::clone(&transport_seq);
    let video_task = app_ref.bundle.runtime.spawn(drain_media_packets_on_plane(
        rx_video,
        Arc::clone(&batching),
        Arc::clone(&cipher),
        false,
        Some(media::LocalMediaPlane::Secondary),
        move |cell| {
            let sender = video_source.current();
            let seq = Arc::clone(&seq_video);
            async move {
                let Some(guard) = cell.sealed.lock_while_fresh(&sender).await else {
                    return true;
                };
                let Some(sender) = guard.as_ref() else {
                    return false;
                };
                let timestamp_us = started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
                let _ = sender
                    .send_rt_data_on_local_lane_before(
                        veil_proto::priority::BULK,
                        peer,
                        peer_app,
                        peer_endpoint_id,
                        seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
                        timestamp_us,
                        cell.marker,
                        cell.payload_type,
                        cell.sealed.as_bytes(),
                        cell.sealed
                            .local_deadline()
                            .expect("native pump retains packet deadline"),
                    )
                    .await;
                true
            }
        },
    ));
    let screen_source = Arc::clone(&screen_sender);
    let screen_task = app_ref.bundle.runtime.spawn(drain_media_packets_on_plane(
        rx_screen,
        Arc::clone(&batching),
        Arc::clone(&cipher),
        false,
        Some(media::LocalMediaPlane::Screen),
        move |cell| {
            let sender = screen_source.current();
            let seq = Arc::clone(&transport_seq);
            async move {
                let Some(guard) = cell.sealed.lock_while_fresh(&sender).await else {
                    return true;
                };
                let Some(sender) = guard.as_ref() else {
                    return false;
                };
                let timestamp_us = started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
                let _ = sender
                    .send_rt_data_on_local_lane_before(
                        veil_proto::priority::BACKGROUND,
                        peer,
                        peer_app,
                        peer_endpoint_id,
                        seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
                        timestamp_us,
                        cell.marker,
                        cell.payload_type,
                        cell.sealed.as_bytes(),
                        cell.sealed
                            .local_deadline()
                            .expect("native pump retains packet deadline"),
                    )
                    .await;
                true
            }
        },
    ));
    let id = MEDIA_NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    MEDIA_CHANNELS
        .write()
        .unwrap_or_else(|p| p.into_inner())
        .insert(
            id,
            MediaChannel {
                path_probe: None,
                ingress: MediaIngress::with_screen(
                    tx_hi,
                    MediaVideoIngress::Packets(tx_video),
                    MediaVideoIngress::Packets(tx_screen),
                ),
                repair_tx: None,
                peer,
                task,
                video_task: Some(video_task),
                screen_task: Some(screen_task),
                video_sender: Some(video_sender),
                screen_sender: Some(screen_sender),
                sender_app_id: Some(app_ref.app_id),
                batching: Some(batching),
                cipher,
                relay_stats: None,
                routes: None,
            },
        );
    id
}

/// Open a lossy MEDIA channel forced through the ordinary Delivery relay path
/// (no onion circuit), sealed end-to-end with the required `tx_key`/`rx_key`
/// (see [`veil_media_open_channel`]). Relay nodes see addressing metadata but
/// never RTP/RTCP bytes. Intended only for direct-identity calls when the
/// preferred P2P route is unavailable.
#[cfg(feature = "node-embedded")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_media_open_relay_channel(
    app: *mut VeilApp,
    peer_node_id: *const u8,
    peer_app_id: *const u8,
    peer_endpoint_id: u32,
    tx_key: *const u8,
    rx_key: *const u8,
    err_out: *mut *mut c_char,
) -> u64 {
    if unsafe { guard::ffi_prelude(err_out, "veil_media_open_relay_channel") }.is_err() {
        return 0;
    }
    null_check_with_default!(err_out, 0u64,
        "app" => app,
        "peer_node_id" => peer_node_id,
        "peer_app_id" => peer_app_id,
        "tx_key" => tx_key,
        "rx_key" => rx_key,
    );
    get_or_return!(app_ref, app_table(), app, err_out, 0u64, "VeilApp");
    let mut peer = [0u8; 32];
    let mut peer_app = [0u8; 32];
    unsafe {
        ptr::copy_nonoverlapping(peer_node_id, peer.as_mut_ptr(), 32);
        ptr::copy_nonoverlapping(peer_app_id, peer_app.as_mut_ptr(), 32);
    }
    let Some(cipher) = (unsafe { media_cipher_from_keys(&peer, tx_key, rx_key, err_out) }) else {
        return 0;
    };

    let (tx_hi, rx_hi) = mpsc::channel::<QueuedMediaPacket>(MEDIA_TX_HI_QUEUE);
    let (tx_video_frames, rx_video_frames) =
        mpsc::channel::<RelayVideoFrame>(RELAY_VIDEO_FRAME_QUEUE);
    let (tx_screen_frames, rx_screen_frames) =
        mpsc::channel::<RelayVideoFrame>(RELAY_VIDEO_FRAME_QUEUE);
    let sender = Arc::clone(&app_ref.sender);
    let video_sender = Arc::new(MediaSenderSlot::new(Arc::clone(&sender)));
    let screen_sender = Arc::new(MediaSenderSlot::new(Arc::clone(&sender)));
    let batching = Arc::new(std::sync::atomic::AtomicU8::new(MEDIA_BATCHING_OFF));
    let relay_stats = Arc::new(RelayMediaStats::default());
    let high_stats = Arc::clone(&relay_stats);
    let task = app_ref.bundle.runtime.spawn(drain_media_packets(
        rx_hi,
        Arc::clone(&batching),
        Arc::clone(&cipher),
        true,
        move |cell| {
            let sender = Arc::clone(&sender);
            let stats = Arc::clone(&high_stats);
            async move {
                let lock_started = std::time::Instant::now();
                let guard = cell.sealed.lock_while_fresh(&sender).await;
                // A wait that expires must remain visible in diagnostics.
                stats.observe_sender_lock(lock_started.elapsed());
                let Some(guard) = guard else {
                    return true;
                };
                let Some(sender) = guard.as_ref() else {
                    return false;
                };
                media::trace_sealed_cell("relay_send", &peer, cell.sealed.as_bytes());
                let ipc_started = std::time::Instant::now();
                let deadline = cell
                    .sealed
                    .local_deadline()
                    .expect("native pump retains packet deadline");
                let result = sender
                    .send_relay_media_sealed_on_local_lane_before_tracked_owned(
                        veil_proto::priority::REALTIME,
                        peer,
                        peer_app,
                        peer_endpoint_id,
                        cell.sealed.into_vec(),
                        deadline,
                        Some(Arc::clone(&stats.ipc_send_failures)),
                    )
                    .await;
                // Ok(false) is expired IPC admission, not a transmitted cell.
                stats.observe_ipc_cell(ipc_started.elapsed(), !matches!(result, Ok(true)));
                true
            }
        },
    ));
    let video_source = Arc::clone(&video_sender);
    let video_stats = Arc::clone(&relay_stats);
    let video_task = app_ref.bundle.runtime.spawn(drain_relay_video(
        rx_video_frames,
        Arc::clone(&batching),
        Arc::clone(&cipher),
        Arc::clone(&relay_stats),
        move |sealed| {
            let sender = video_source.current();
            let stats = Arc::clone(&video_stats);
            async move {
                let lock_started = std::time::Instant::now();
                let guard = sealed.lock_while_fresh(&sender).await;
                stats.observe_sender_lock(lock_started.elapsed());
                let Some(guard) = guard else {
                    return true;
                };
                let Some(sender) = guard.as_ref() else {
                    return false;
                };
                let ipc_started = std::time::Instant::now();
                let deadline = sealed
                    .local_deadline()
                    .expect("native pump retains packet deadline");
                let result = sender
                    .send_relay_media_sealed_on_local_lane_before_tracked_owned(
                        veil_proto::priority::BULK,
                        peer,
                        peer_app,
                        peer_endpoint_id,
                        sealed.into_vec(),
                        deadline,
                        Some(Arc::clone(&stats.ipc_send_failures)),
                    )
                    .await;
                stats.observe_ipc_cell(ipc_started.elapsed(), !matches!(result, Ok(true)));
                true
            }
        },
    ));
    let screen_source = Arc::clone(&screen_sender);
    let screen_stats = Arc::clone(&relay_stats);
    let screen_task = app_ref.bundle.runtime.spawn(drain_relay_video_on_plane(
        rx_screen_frames,
        Arc::clone(&batching),
        Arc::clone(&cipher),
        Arc::clone(&relay_stats),
        media::LocalMediaPlane::Screen,
        move |sealed| {
            let sender = screen_source.current();
            let stats = Arc::clone(&screen_stats);
            async move {
                let lock_started = std::time::Instant::now();
                let guard = sealed.lock_while_fresh(&sender).await;
                stats.observe_sender_lock(lock_started.elapsed());
                let Some(guard) = guard else {
                    return true;
                };
                let Some(sender) = guard.as_ref() else {
                    return false;
                };
                let ipc_started = std::time::Instant::now();
                let deadline = sealed
                    .local_deadline()
                    .expect("native pump retains packet deadline");
                let result = sender
                    .send_relay_media_sealed_on_local_lane_before_tracked_owned(
                        veil_proto::priority::BACKGROUND,
                        peer,
                        peer_app,
                        peer_endpoint_id,
                        sealed.into_vec(),
                        deadline,
                        Some(Arc::clone(&stats.ipc_send_failures)),
                    )
                    .await;
                stats.observe_ipc_cell(ipc_started.elapsed(), !matches!(result, Ok(true)));
                true
            }
        },
    ));
    let id = MEDIA_NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    MEDIA_CHANNELS
        .write()
        .unwrap_or_else(|p| p.into_inner())
        .insert(
            id,
            MediaChannel {
                path_probe: None,
                ingress: MediaIngress::with_screen(
                    tx_hi,
                    MediaVideoIngress::relay_frames(tx_video_frames, Arc::clone(&relay_stats)),
                    MediaVideoIngress::relay_frames(tx_screen_frames, Arc::clone(&relay_stats)),
                ),
                repair_tx: None,
                peer,
                task,
                video_task: Some(video_task),
                screen_task: Some(screen_task),
                video_sender: Some(video_sender),
                screen_sender: Some(screen_sender),
                sender_app_id: Some(app_ref.app_id),
                batching: Some(batching),
                cipher,
                relay_stats: Some(relay_stats),
                routes: None,
            },
        );
    id
}

/// Set the channel's secondary local IPC sender before starting media. It must
/// bind the same application identity as the primary sender. No sender role
/// or local endpoint id is added to network packets. Returns 0 on success,
/// -1 on an invalid channel/app or an anonymous channel without this plane.
#[cfg(feature = "node-embedded")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_media_channel_set_secondary_sender(
    chan: u64,
    app: *mut VeilApp,
    err_out: *mut *mut c_char,
) -> c_int {
    if unsafe { guard::ffi_prelude(err_out, "veil_media_channel_set_secondary_sender") }.is_err() {
        return -1;
    }
    null_check_with_default!(err_out, -1, "app" => app);
    get_or_return!(app_ref, app_table(), app, err_out, -1, "VeilApp");
    let channels = MEDIA_CHANNELS.read().unwrap_or_else(|p| p.into_inner());
    let Some(channel) = channels.get(&chan) else {
        unsafe { write_err(err_out, "unknown media channel") };
        return -1;
    };
    if channel.sender_app_id != Some(app_ref.app_id) {
        unsafe { write_err(err_out, "secondary sender must have the same app identity") };
        return -1;
    }
    let Some(slot) = channel.video_sender.as_ref() else {
        unsafe { write_err(err_out, "media channel has no secondary IPC plane") };
        return -1;
    };
    slot.replace(Arc::clone(&app_ref.sender));
    0
}

/// Set the channel's screen local IPC sender before starting media. It must
/// bind the same application identity as the primary sender. No sender role
/// or local endpoint id is added to network packets. Returns 0 on success,
/// -1 on an invalid channel/app or an anonymous channel without this plane.
#[cfg(feature = "node-embedded")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_media_channel_set_screen_sender(
    chan: u64,
    app: *mut VeilApp,
    err_out: *mut *mut c_char,
) -> c_int {
    if unsafe { guard::ffi_prelude(err_out, "veil_media_channel_set_screen_sender") }.is_err() {
        return -1;
    }
    null_check_with_default!(err_out, -1, "app" => app);
    get_or_return!(app_ref, app_table(), app, err_out, -1, "VeilApp");
    let channels = MEDIA_CHANNELS.read().unwrap_or_else(|p| p.into_inner());
    let Some(channel) = channels.get(&chan) else {
        unsafe { write_err(err_out, "unknown media channel") };
        return -1;
    };
    if channel.sender_app_id != Some(app_ref.app_id) {
        unsafe { write_err(err_out, "screen sender must have the same app identity") };
        return -1;
    }
    let Some(slot) = channel.screen_sender.as_ref() else {
        unsafe { write_err(err_out, "media channel has no screen IPC plane") };
        return -1;
    };
    slot.replace(Arc::clone(&app_ref.sender));
    0
}

/// Select the local screen producer before starting capture; clear after it
/// stops. RTP is still sealed in the same role-free wire format. Returns -1
/// for a closed/invalid channel or a channel without screen ingress.
#[cfg(feature = "node-embedded")]
#[unsafe(no_mangle)]
pub extern "C" fn veil_media_channel_set_screen_sharing(chan: u64, on: c_int) -> c_int {
    if on != 0 && on != 1 {
        return -1;
    }
    let map = MEDIA_CHANNELS.read().unwrap_or_else(|p| p.into_inner());
    let Some(channel) = map.get(&chan) else {
        return -1;
    };
    if channel.ingress.screen.is_none()
        || channel
            .ingress
            .closed
            .load(std::sync::atomic::Ordering::Acquire)
    {
        return -1;
    }
    channel
        .ingress
        .screen_sharing
        .store(on != 0, std::sync::atomic::Ordering::Release);
    0
}

/// Enqueue one media datagram (RTP/RTCP) on `chan`. NON-BLOCKING: returns 0 if
/// queued, 1 if dropped (full queue / busy ingress) — the caller's real-time
/// media thread must never block. Returns -1 on a NULL/zero-length payload or an
/// unknown/closed `chan`.
#[cfg(feature = "node-embedded")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_media_send_datagram(chan: u64, ptr: *const u8, len: size_t) -> c_int {
    if chan == 0 || ptr.is_null() || len == 0 {
        return -1;
    }
    // Clone only ingress, never the channel/keys/pump owner. No registry guard
    // can reach RTP classification, allocation or video frame assembly.
    let ingress = {
        let map = match MEDIA_CHANNELS.try_read() {
            Ok(map) => map,
            Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => {
                return refuse_ingress(
                    IngressRefusal::RegistryBusy,
                    media_is_vp8_rtp(unsafe { std::slice::from_raw_parts(ptr, len) }),
                    1,
                );
            }
        };
        let Some(ch) = map.get(&chan) else {
            return refuse_ingress(
                IngressRefusal::UnknownChannel,
                media_is_vp8_rtp(unsafe { std::slice::from_raw_parts(ptr, len) }),
                -1,
            );
        };
        Arc::clone(&ch.ingress)
    };
    let payload = QueuedMediaPacket::from(unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec());
    ingress.enqueue(payload)
}

/// Enqueue video-engine RTCP on the channel's independent local video source.
/// Screen sharing selects its independent source instead. This is endpoint
/// scheduling only: no media role or priority is added to relay framing.
/// Compound RTCP is validated; RTP and malformed control return -1. Admission
/// remains nonblocking (0 queued, 1 full/busy, -1 invalid/closed), with no
/// fallback into the audio queue when the selected source is full.
#[cfg(feature = "node-embedded")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_media_send_video_control_datagram(
    chan: u64,
    ptr: *const u8,
    len: size_t,
) -> c_int {
    if chan == 0 || ptr.is_null() || len == 0 {
        return -1;
    }
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    if !media_is_rtcp(bytes) {
        return -1;
    }
    let ingress = {
        let map = match MEDIA_CHANNELS.try_read() {
            Ok(map) => map,
            Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => {
                return refuse_ingress(IngressRefusal::RegistryBusy, true, 1);
            }
        };
        let Some(ch) = map.get(&chan) else {
            return refuse_ingress(IngressRefusal::UnknownChannel, true, -1);
        };
        Arc::clone(&ch.ingress)
    };
    ingress.enqueue_video_control(QueuedMediaPacket::from(bytes.to_vec()))
}

/// Snapshot per-channel relay drain diagnostics. Direct/onion channels return
/// a zeroed snapshot. Returns -1 for an invalid channel or null output.
#[cfg(feature = "node-embedded")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_media_channel_get_stats(
    chan: u64,
    out: *mut VeilMediaChannelStats,
) -> c_int {
    if chan == 0 || out.is_null() {
        return -1;
    }
    let map = MEDIA_CHANNELS.read().unwrap_or_else(|p| p.into_inner());
    let Some(ch) = map.get(&chan) else {
        return -1;
    };
    let snapshot = ch
        .relay_stats
        .as_ref()
        .map_or_else(VeilMediaChannelStats::default, |stats| stats.snapshot());
    unsafe { out.write(snapshot) };
    0
}

/// Request a make-before-break anonymous route refresh for an open media
/// channel. This is deliberately separate from send success: an onion packet
/// can enter the first-hop queue successfully and still be black-holed farther
/// along the circuit. The peer reports that end-to-end silence over the live
/// call heartbeat, and the host forwards it here. Returns 0 when queued, 1 when
/// an equivalent repair is already pending, and -1 for an unknown/direct
/// channel.
#[cfg(feature = "node-embedded")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_media_repair_channel(chan: u64) -> c_int {
    if chan == 0 {
        return -1;
    }
    let map = MEDIA_CHANNELS.read().unwrap_or_else(|p| p.into_inner());
    let Some(repair_tx) = map.get(&chan).and_then(|ch| ch.repair_tx.as_ref()) else {
        return -1;
    };
    let mut queued = false;
    let mut pending = false;
    for tx in repair_tx {
        match tx.try_send(()) {
            Ok(()) => queued = true,
            Err(mpsc::error::TrySendError::Full(_)) => pending = true,
            Err(mpsc::error::TrySendError::Closed(_)) => {}
        }
    }
    if queued {
        if let Some(routes) = map.get(&chan).and_then(|ch| ch.routes.as_ref()) {
            routes.repair();
        }
        0
    } else if pending {
        1
    } else {
        -1
    }
}

/// Select media batching for a direct or relay channel: 0 = off, 1 = legacy
/// audio+video batching, 2 = compact relay audio-only batching. Mode 2 is
/// rejected for non-relay channels. This is a WIRE-FORMAT selector, not a
/// security one — every mode seals identically, and the batch envelope now
/// travels inside the seal, so a peer on the path cannot see or rewrite it.
/// Returns 0 on success, -1 for an unknown/unsupported channel or mode.
#[cfg(feature = "node-embedded")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_media_channel_set_batching(chan: u64, mode: c_int) -> c_int {
    let map = MEDIA_CHANNELS.read().unwrap_or_else(|p| p.into_inner());
    let Some(ch) = map.get(&chan) else {
        return -1;
    };
    let Some(b) = ch.batching.as_ref() else {
        return -1;
    };
    let Ok(mode) = u8::try_from(mode) else {
        return -1;
    };
    if !matches!(
        mode,
        MEDIA_BATCHING_OFF | MEDIA_BATCHING_LEGACY | MEDIA_BATCHING_COMPACT_RELAY
    ) {
        return -1;
    }
    if mode == MEDIA_BATCHING_COMPACT_RELAY && ch.relay_stats.is_none() {
        return -1;
    }
    b.store(mode, std::sync::atomic::Ordering::Relaxed);
    0
}

/// Feed one direct-P2P media datagram received by the host on the media app
/// endpoint into the shared native media ingress. Whatever the host believes
/// about the source, the cell is opened with the channel's own key before a
/// byte of it reaches the engine.
#[cfg(feature = "node-embedded")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_media_dispatch_direct_datagram(
    peer_node_id: *const u8,
    ptr: *const u8,
    len: size_t,
) -> c_int {
    if peer_node_id.is_null() || ptr.is_null() || len == 0 {
        return -1;
    }
    let mut peer = [0u8; 32];
    unsafe {
        ptr::copy_nonoverlapping(peer_node_id, peer.as_mut_ptr(), 32);
    }
    let payload = unsafe { std::slice::from_raw_parts(ptr, len) };
    media::dispatch_inbound_auto(peer, payload);
    0
}

#[cfg(feature = "node-embedded")]
pub(crate) fn direct_media_source_app(node_id: &[u8; 32], namespace: &str, name: &str) -> [u8; 32] {
    veil_app::app_id(node_id, namespace, name)
}

/// Drain one bound app endpoint directly into the native media callback
/// registry, bypassing the host language's event loop entirely.
///
/// `source_namespace` + `source_name` identify the well-known named app that a
/// remote media sender must use. The delivery's `src_node_id` is combined with
/// those names to derive the only accepted `src_app_id`; frames from another
/// app on the same peer are silently dropped. This preserves the source-app
/// check previously performed in Dart without copying every RTP packet through
/// the UI isolate.
///
/// X/V-01, stated plainly because the sentence above used to call that id "the
/// authenticated session `src_node_id`" and nothing here checks it: the derived
/// app id is a function OF `src_node_id`, so anyone who can claim a node id can
/// also compute its media app id. This demux is not, and never was, a sender
/// gate. `provenance` is deliberately NOT consulted here either — media
/// legitimately arrives over anonymous ingress, which is `Claimed` by design, so
/// refusing it would break calls rather than secure them. What authenticates a
/// media sender is the per-channel `MediaCipher` seal, which every channel now
/// has and which [`media::dispatch_inbound_auto`] applies to every cell on every
/// transport.
///
/// This function takes exclusive ownership of the app's datagram receiver. It
/// must be called before [`veil_app_set_recv_handler`].
#[cfg(feature = "node-embedded")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_media_start_direct_receiver(
    app: *mut VeilApp,
    source_namespace: *const u8,
    source_namespace_len: size_t,
    source_name: *const u8,
    source_name_len: size_t,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_media_start_direct_receiver") } {
        return rc;
    }
    null_check!(err_out,
        "app" => app,
        "source_namespace" => source_namespace,
        "source_name" => source_name,
    );
    get_or_return!(
        app_ref,
        app_table(),
        app,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilApp"
    );
    let namespace = match std::str::from_utf8(unsafe {
        std::slice::from_raw_parts(source_namespace, source_namespace_len)
    }) {
        Ok(v) => v.to_owned(),
        Err(_) => {
            unsafe { write_err(err_out, "source_namespace is not valid UTF-8") };
            return VEIL_ERR_INVALID_ARG;
        }
    };
    let name = match std::str::from_utf8(unsafe {
        std::slice::from_raw_parts(source_name, source_name_len)
    }) {
        Ok(v) => v.to_owned(),
        Err(_) => {
            unsafe { write_err(err_out, "source_name is not valid UTF-8") };
            return VEIL_ERR_INVALID_ARG;
        }
    };
    if namespace.is_empty() || name.is_empty() {
        unsafe { write_err(err_out, "source namespace/name must be non-empty") };
        return VEIL_ERR_INVALID_ARG;
    }

    let mut receiver_guard = app_ref.msg_rx.blocking_lock();
    let mut task_guard = app_ref.recv_task.lock().unwrap_or_else(|e| e.into_inner());
    if task_guard.is_some() {
        unsafe { write_err(err_out, "app receiver already has a handler") };
        return VEIL_ERR_CLOSED;
    }
    let Some(mut msg_rx) = receiver_guard.take() else {
        unsafe { write_err(err_out, "app receiver is closed") };
        return VEIL_ERR_CLOSED;
    };
    let task = app_ref.bundle.runtime.spawn(async move {
        while let Some(IncomingMessage {
            src_node_id,
            src_app_id,
            data,
            ..
        }) = msg_rx.recv().await
        {
            // Compute rather than cache by untrusted sender id: the media
            // endpoint is long-lived, so a stream of one-shot authenticated
            // peers must not grow an unbounded source-id map.
            // Count what ARRIVES, not only what is refused. "No mismatch
            // logged" was read as "the demux is fine" when it equally meant
            // "nothing ever reached the demux" — the two are opposite
            // diagnoses and the instrument could not tell them apart.
            {
                use std::sync::atomic::{AtomicU64, Ordering};
                static ARRIVED: AtomicU64 = AtomicU64::new(0);
                let n = ARRIVED.fetch_add(1, Ordering::Relaxed) + 1;
                if n == 1 || n.is_multiple_of(500) {
                    log::info!(
                        "media.ingress.arrived n={n} from={} bytes={}",
                        veil_util::bytes_to_hex(&src_node_id[..4]),
                        data.len(),
                    );
                }
            }
            let expected = direct_media_source_app(&src_node_id, &namespace, &name);
            if src_app_id != expected {
                // SAY SO. This demux dropped every mismatching frame in
                // silence, and silence here is indistinguishable from "the
                // network delivered nothing": the engine reports
                // packets_received=0, `dispatch MISS` never fires because the
                // frame never reaches the dispatch, and every layer above
                // looks healthy while sending works perfectly.
                //
                // Counted, not logged per frame: media arrives at about fifty
                // frames a second, and an unthrottled line would bury the
                // answer it is meant to give.
                use std::sync::atomic::{AtomicU64, Ordering};
                static MISMATCHES: AtomicU64 = AtomicU64::new(0);
                let n = MISMATCHES.fetch_add(1, Ordering::Relaxed) + 1;
                if n == 1 || n.is_multiple_of(500) {
                    log::warn!(
                        "media.source_app.mismatch dropped {n} frame(s) from \
                         peer={} — src_app_id={} expected={} (ns={namespace} \
                         name={name})",
                        veil_util::bytes_to_hex(&src_node_id[..4]),
                        veil_util::bytes_to_hex(&src_app_id[..8]),
                        veil_util::bytes_to_hex(&expected[..8]),
                    );
                }
                continue;
            }
            media::dispatch_inbound_auto(src_node_id, &data);
        }
    });
    *task_guard = Some(task);
    VEIL_OK
}

/// Install the C recv callback invoked (native↔native, from a tokio worker)
/// once per authenticated inbound media datagram from `chan`'s peer, with the
/// wire magic already stripped. Configured path probes pin the identity and
/// physical-device addresses of this same call: register both before media
/// starts so the peer may change its sender while ours still uses the old
/// route. Both addresses use one cipher/replay window and callback owner.
/// Replaces prior callbacks; `cb == NULL` clears every alias owned by `chan`.
/// Returns 0, or -1 on an unknown `chan`.
#[cfg(feature = "node-embedded")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_media_set_recv_callback(
    chan: u64,
    cb: Option<media::MediaRecvFn>,
    ctx: *mut c_void,
) -> c_int {
    let channel = {
        let map = MEDIA_CHANNELS.read().unwrap_or_else(|p| p.into_inner());
        map.get(&chan).map(|ch| {
            let peers = ch
                .path_probe
                .as_ref()
                .map_or([ch.peer; 2], |path| path.receive_peers());
            (peers, Arc::clone(&ch.cipher))
        })
    };
    match (cb, channel) {
        (Some(cb), Some((peers, cipher))) => {
            media::set_recv_callback(peers[0], chan, cb, ctx, Arc::clone(&cipher));
            if peers[1] != peers[0] {
                media::set_recv_callback(peers[1], chan, cb, ctx, cipher);
            }
        }
        // Registering on an unknown channel has nowhere to route — error out.
        (Some(_), None) => return -1,
        // Clearing must ALWAYS land: when the host closed the channel before
        // the engine unregistered, the peer key can't be resolved anymore, yet
        // leaving the stale registration would keep swallowing the peer's
        // inbound media into a stopped receiver. Sweep by owner chan instead.
        (None, _) => media::clear_recv_callback_by_chan(chan),
    }
    0
}

/// Close a media channel: stops all producer tasks, drops the outbound queues, and
/// clears the peer's recv callback. Idempotent (unknown `chan` is a no-op).
#[cfg(feature = "node-embedded")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_media_close_channel(chan: u64) {
    let ch = MEDIA_CHANNELS
        .write()
        .unwrap_or_else(|p| p.into_inner())
        .remove(&chan);
    if let Some(ch) = ch {
        // Stop outbound work before waiting for an in-flight recv callback.
        ch.abort_pumps();
        media::clear_recv_callback_by_chan(chan);
    }
}

/// Diagnostic: number of inbound media datagrams received from `peer_node_id`
/// (32 bytes) since process start. Lets a host confirm receipt without wiring a
/// cross-thread recv callback (used by the Phase 2 two-node datagram probe).
/// Returns 0 on a NULL pointer.
#[cfg(feature = "node-embedded")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_media_recv_count(peer_node_id: *const u8) -> u64 {
    if peer_node_id.is_null() {
        return 0;
    }
    let mut peer = [0u8; 32];
    unsafe {
        ptr::copy_nonoverlapping(peer_node_id, peer.as_mut_ptr(), 32);
    }
    media::recv_count(peer)
}

// ── the plane these calls drive ──────────────────────────────────────
//
// Lifted out of `lib.rs` together with the calls above: the bounded
// outbound queue, the relay video-frame assembler and the wire-cell
// builder have no caller anywhere else.

// ---------------------------------------------------------------------------
// Media datagram channel (Phase 2 of calls): a lossy RTP/RTCP path over the
// anonymous onion circuit. Per-packet flow is native↔native (a C++/ObjC++
// `webrtc::Transport` shim calls `veil_media_send_datagram` and receives via
// `veil_media_set_recv_callback`); Dart drives control only (open/close). See
// `media.rs` for the wire magic + inbound registry and `veil_media_abi.h` for
// the shared header.
// ---------------------------------------------------------------------------

/// One open media channel. Holds a BOUNDED outbound queue and the drain task
/// that pumps it into the hub's lossy datagram send. Bounded because real-time
/// media must drop rather than buffer when it outpaces the circuit.
#[cfg(feature = "node-embedded")]
struct MediaChannel {
    path_probe: Option<Arc<path_probe_ffi::PathProbeContext>>,
    ingress: Arc<MediaIngress>,
    /// Anonymous channels accept an out-of-band end-to-end repair request.
    /// The receiver of the media asks the sender to refresh its outbound
    /// rendezvous pool when RTP/RTCP has gone dark even though signaling is
    /// still alive. Direct channels leave this `None`.
    repair_tx: Option<[mpsc::Sender<()>; 3]>,
    peer: [u8; 32],
    task: tokio::task::JoinHandle<()>,
    video_task: Option<tokio::task::JoinHandle<()>>,
    screen_task: Option<tokio::task::JoinHandle<()>>,
    video_sender: Option<Arc<MediaSenderSlot<AppSender>>>,
    screen_sender: Option<Arc<MediaSenderSlot<AppSender>>>,
    sender_app_id: Option<[u8; 32]>,
    /// Opt-in media batching on direct/RELAY send paths (see
    /// `veil_media_channel_set_batching`). Off by default: a batched cell is
    /// silent noise to a legacy receiver, so the host enables it only after
    /// call signaling proves the peer's protocol version understands
    /// MEDIA_BATCH_MAGIC on this path. `None` on onion channels (their own
    /// transport already batches).
    batching: Option<Arc<std::sync::atomic::AtomicU8>>,
    /// The channel's end-to-end media cipher — required, on every transport.
    /// The same object is installed with the receive callback, so route
    /// rebuilds do not race separate TX/RX cipher ownership, and there is no
    /// state in which a channel exists but its media is in the clear.
    cipher: Arc<media::MediaCipher>,
    /// Relay-only drain telemetry. Atomics keep the real-time ingress ABI
    /// non-blocking while letting the host distinguish a local queue stall
    /// from delay after the frame has entered the node/session path.
    relay_stats: Option<Arc<RelayMediaStats>>,
    routes: Option<Arc<anon_stream::MediaRoutes>>,
}

#[cfg(feature = "node-embedded")]
impl MediaChannel {
    fn abort_pumps(&self) {
        self.ingress
            .closed
            .store(true, std::sync::atomic::Ordering::Release);
        if let Some(probe) = &self.path_probe {
            probe.cancel();
        }
        if let Some(routes) = &self.routes {
            routes.stop();
        }
        self.task.abort();
        if let Some(video_task) = self.video_task.as_ref() {
            video_task.abort();
        }
        if let Some(screen_task) = &self.screen_task {
            screen_task.abort();
        }
    }
}

#[cfg(feature = "node-embedded")]
impl Drop for MediaChannel {
    fn drop(&mut self) {
        self.abort_pumps();
    }
}

/// Packet ingress is sufficient for onion/P2P because their drain paths accept
/// packets as quickly as WebRTC emits them. A relayed send performs more work
/// per packet (E2E envelope + relay routing), so a tiny packet FIFO can retain
/// only the first few fragments of a VP8 keyframe. Buffer relay video by RTP
/// frame instead: a frame is either admitted whole or dropped whole.
#[cfg(feature = "node-embedded")]
enum MediaVideoIngress {
    Packets(mpsc::Sender<QueuedMediaPacket>),
    RelayFrames {
        tx: mpsc::Sender<RelayVideoFrame>,
        assembler: StdMutex<RelayVideoFrameAssembler>,
        contended: std::sync::atomic::AtomicBool,
        stats: Arc<RelayMediaStats>,
    },
}

/// Send callbacks retain only this bounded plaintext ingress. Closing the
/// owner marks it unavailable even while a callback/diagnostic clone survives.
#[cfg(feature = "node-embedded")]
struct MediaIngress {
    tx_hi: mpsc::Sender<QueuedMediaPacket>,
    video: MediaVideoIngress,
    screen: Option<MediaVideoIngress>,
    screen_sharing: std::sync::atomic::AtomicBool,
    closed: std::sync::atomic::AtomicBool,
}

#[cfg(feature = "node-embedded")]
impl MediaVideoIngress {
    fn relay_frames(tx: mpsc::Sender<RelayVideoFrame>, stats: Arc<RelayMediaStats>) -> Self {
        Self::RelayFrames {
            tx,
            assembler: StdMutex::new(RelayVideoFrameAssembler::default()),
            contended: std::sync::atomic::AtomicBool::new(false),
            stats,
        }
    }
}

#[cfg(feature = "node-embedded")]
impl MediaIngress {
    #[cfg(test)]
    fn new(tx_hi: mpsc::Sender<QueuedMediaPacket>, video: MediaVideoIngress) -> Arc<Self> {
        Self::make(tx_hi, video, None)
    }

    fn with_screen(
        tx_hi: mpsc::Sender<QueuedMediaPacket>,
        video: MediaVideoIngress,
        screen: MediaVideoIngress,
    ) -> Arc<Self> {
        Self::make(tx_hi, video, Some(screen))
    }

    fn make(
        tx_hi: mpsc::Sender<QueuedMediaPacket>,
        video: MediaVideoIngress,
        screen: Option<MediaVideoIngress>,
    ) -> Arc<Self> {
        ingress_diagnostics::start();
        Arc::new(Self {
            tx_hi,
            video,
            screen,
            screen_sharing: std::sync::atomic::AtomicBool::new(false),
            closed: std::sync::atomic::AtomicBool::new(false),
        })
    }

    fn enqueue(&self, payload: QueuedMediaPacket) -> c_int {
        use std::sync::atomic::Ordering::{AcqRel, Acquire};
        if self.closed.load(Acquire) {
            return refuse_ingress(
                IngressRefusal::IngressClosed,
                media_is_vp8_rtp(&payload.payload),
                -1,
            );
        }
        if !media_is_vp8_rtp(&payload.payload) {
            return Self::send_packet(&self.tx_hi, payload, false);
        }
        let source = if self.screen_sharing.load(Acquire) {
            match &self.screen {
                Some(screen) => screen,
                None => return refuse_ingress(IngressRefusal::MissingScreen, true, -1),
            }
        } else {
            &self.video
        };
        match source {
            MediaVideoIngress::Packets(tx) => Self::send_packet(tx, payload, true),
            MediaVideoIngress::RelayFrames {
                tx,
                assembler,
                contended,
                stats,
            } => {
                let mut assembler = match assembler.try_lock() {
                    Ok(assembler) => assembler,
                    Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner(),
                    Err(std::sync::TryLockError::WouldBlock) => {
                        contended.store(true, std::sync::atomic::Ordering::Release);
                        return refuse_ingress(IngressRefusal::AssemblerBusy, true, 1);
                    }
                };
                if contended.swap(false, AcqRel) {
                    assembler.discard_after_contention();
                }
                let result = assembler.push(payload.payload);
                if contended.swap(false, AcqRel) {
                    // A concurrent callback dropped a fragment while this
                    // callback was building the frame. Discard its prefix/tail.
                    assembler.discard_after_contention();
                    return refuse_ingress(IngressRefusal::AssemblerBusy, true, 1);
                }
                if self.closed.load(Acquire) {
                    return refuse_ingress(IngressRefusal::IngressClosed, true, -1);
                }
                match result {
                    RelayVideoFramePush::Pending => 0,
                    RelayVideoFramePush::Dropped => {
                        refuse_ingress(IngressRefusal::IncompleteFrame, true, 1)
                    }
                    RelayVideoFramePush::Complete(packets) => {
                        stats.enqueue_frame();
                        let frame = RelayVideoFrame {
                            packets,
                            enqueued_at: std::time::Instant::now(),
                        };
                        match tx.try_send(frame) {
                            Ok(()) => 0,
                            Err(mpsc::error::TrySendError::Full(_)) => {
                                stats.undo_enqueue_frame();
                                refuse_ingress(IngressRefusal::FrameQueueFull, true, 1)
                            }
                            Err(mpsc::error::TrySendError::Closed(_)) => {
                                stats.undo_enqueue_frame();
                                refuse_ingress(IngressRefusal::FrameQueueClosed, true, -1)
                            }
                        }
                    }
                }
            }
        }
    }

    fn enqueue_video_control(&self, payload: QueuedMediaPacket) -> c_int {
        use std::sync::atomic::Ordering::Acquire;
        if self.closed.load(Acquire) {
            return refuse_ingress(IngressRefusal::IngressClosed, true, -1);
        }
        let source = if self.screen_sharing.load(Acquire) {
            match &self.screen {
                Some(screen) => screen,
                None => return refuse_ingress(IngressRefusal::MissingScreen, true, -1),
            }
        } else {
            &self.video
        };
        match source {
            MediaVideoIngress::Packets(tx) => Self::send_packet(tx, payload, true),
            MediaVideoIngress::RelayFrames { tx, stats, .. } => {
                // Control is an independently complete work item. It must not
                // consume or discard a partially assembled VP8 frame.
                let frame = RelayVideoFrame {
                    enqueued_at: payload.deadline.into_std() - MEDIA_LOCAL_QUEUE_AGE,
                    packets: vec![payload.payload],
                };
                stats.enqueue_frame();
                match tx.try_send(frame) {
                    Ok(()) => 0,
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        stats.undo_enqueue_frame();
                        refuse_ingress(IngressRefusal::FrameQueueFull, true, 1)
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        stats.undo_enqueue_frame();
                        refuse_ingress(IngressRefusal::FrameQueueClosed, true, -1)
                    }
                }
            }
        }
    }

    fn send_packet(
        tx: &mpsc::Sender<QueuedMediaPacket>,
        payload: QueuedMediaPacket,
        secondary: bool,
    ) -> c_int {
        match tx.try_send(payload) {
            Ok(()) => 0,
            Err(mpsc::error::TrySendError::Full(_)) => {
                refuse_ingress(IngressRefusal::PacketQueueFull, secondary, 1)
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                refuse_ingress(IngressRefusal::PacketQueueClosed, secondary, -1)
            }
        }
    }
}

#[cfg(feature = "node-embedded")]
struct RelayVideoFrame {
    packets: Vec<Vec<u8>>,
    enqueued_at: std::time::Instant,
}

/// Stable C snapshot returned by `veil_media_channel_get_stats`. All fields
/// are cumulative channel-lifetime counters/maxima except `video_queue_depth`.
/// Keep this plain-u64 layout in lockstep with Dart's FFI struct.
#[cfg(feature = "node-embedded")]
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct VeilMediaChannelStats {
    pub video_frames_enqueued: u64,
    pub video_frames_started: u64,
    pub video_queue_depth: u64,
    pub video_queue_max_depth: u64,
    pub video_queue_age_max_ms: u64,
    pub video_queue_holds_75ms: u64,
    pub sender_lock_max_ms: u64,
    pub sender_lock_holds_16ms: u64,
    pub video_frame_ipc_max_ms: u64,
    pub video_frame_ipc_holds_33ms: u64,
    pub ipc_cell_max_ms: u64,
    pub ipc_cell_holds_16ms: u64,
    pub ipc_send_failures: u64,
}

#[cfg(feature = "node-embedded")]
#[derive(Default)]
struct RelayMediaStats {
    video_frames_enqueued: std::sync::atomic::AtomicU64,
    video_frames_started: std::sync::atomic::AtomicU64,
    video_queue_depth: std::sync::atomic::AtomicU64,
    video_queue_max_depth: std::sync::atomic::AtomicU64,
    video_queue_age_max_ms: std::sync::atomic::AtomicU64,
    video_queue_holds_75ms: std::sync::atomic::AtomicU64,
    sender_lock_max_ms: std::sync::atomic::AtomicU64,
    sender_lock_holds_16ms: std::sync::atomic::AtomicU64,
    video_frame_ipc_max_ms: std::sync::atomic::AtomicU64,
    video_frame_ipc_holds_33ms: std::sync::atomic::AtomicU64,
    ipc_cell_max_ms: std::sync::atomic::AtomicU64,
    ipc_cell_holds_16ms: std::sync::atomic::AtomicU64,
    ipc_send_failures: Arc<std::sync::atomic::AtomicU64>,
}

#[cfg(feature = "node-embedded")]
impl RelayMediaStats {
    fn millis(elapsed: std::time::Duration) -> u64 {
        elapsed.as_millis().min(u64::MAX as u128) as u64
    }

    fn enqueue_frame(&self) {
        use std::sync::atomic::Ordering::Relaxed;
        self.video_frames_enqueued.fetch_add(1, Relaxed);
        let depth = self.video_queue_depth.fetch_add(1, Relaxed) + 1;
        self.video_queue_max_depth.fetch_max(depth, Relaxed);
    }

    fn undo_enqueue_frame(&self) {
        use std::sync::atomic::Ordering::Relaxed;
        self.video_frames_enqueued.fetch_sub(1, Relaxed);
        self.video_queue_depth.fetch_sub(1, Relaxed);
    }

    fn start_frame(&self, queued_for: std::time::Duration) {
        use std::sync::atomic::Ordering::Relaxed;
        self.video_queue_depth.fetch_sub(1, Relaxed);
        self.video_frames_started.fetch_add(1, Relaxed);
        let ms = Self::millis(queued_for);
        self.video_queue_age_max_ms.fetch_max(ms, Relaxed);
        if ms >= 75 {
            self.video_queue_holds_75ms.fetch_add(1, Relaxed);
        }
    }

    fn observe_sender_lock(&self, elapsed: std::time::Duration) {
        use std::sync::atomic::Ordering::Relaxed;
        let ms = Self::millis(elapsed);
        self.sender_lock_max_ms.fetch_max(ms, Relaxed);
        if ms >= 16 {
            self.sender_lock_holds_16ms.fetch_add(1, Relaxed);
        }
    }

    fn observe_frame_ipc(&self, elapsed: std::time::Duration) {
        use std::sync::atomic::Ordering::Relaxed;
        let ms = Self::millis(elapsed);
        self.video_frame_ipc_max_ms.fetch_max(ms, Relaxed);
        if ms >= 33 {
            self.video_frame_ipc_holds_33ms.fetch_add(1, Relaxed);
        }
    }

    fn observe_ipc_cell(&self, elapsed: std::time::Duration, failed: bool) {
        use std::sync::atomic::Ordering::Relaxed;
        let ms = Self::millis(elapsed);
        self.ipc_cell_max_ms.fetch_max(ms, Relaxed);
        if ms >= 16 {
            self.ipc_cell_holds_16ms.fetch_add(1, Relaxed);
        }
        if failed {
            self.ipc_send_failures.fetch_add(1, Relaxed);
        }
    }

    fn snapshot(&self) -> VeilMediaChannelStats {
        use std::sync::atomic::Ordering::Relaxed;
        VeilMediaChannelStats {
            video_frames_enqueued: self.video_frames_enqueued.load(Relaxed),
            video_frames_started: self.video_frames_started.load(Relaxed),
            video_queue_depth: self.video_queue_depth.load(Relaxed),
            video_queue_max_depth: self.video_queue_max_depth.load(Relaxed),
            video_queue_age_max_ms: self.video_queue_age_max_ms.load(Relaxed),
            video_queue_holds_75ms: self.video_queue_holds_75ms.load(Relaxed),
            sender_lock_max_ms: self.sender_lock_max_ms.load(Relaxed),
            sender_lock_holds_16ms: self.sender_lock_holds_16ms.load(Relaxed),
            video_frame_ipc_max_ms: self.video_frame_ipc_max_ms.load(Relaxed),
            video_frame_ipc_holds_33ms: self.video_frame_ipc_holds_33ms.load(Relaxed),
            ipc_cell_max_ms: self.ipc_cell_max_ms.load(Relaxed),
            ipc_cell_holds_16ms: self.ipc_cell_holds_16ms.load(Relaxed),
            ipc_send_failures: self.ipc_send_failures.load(Relaxed),
        }
    }
}

/// Open media channels keyed by the opaque id handed to the host.
#[cfg(feature = "node-embedded")]
// Read-only stats, sender selection and RTP callbacks share the registry.
// An exclusive mutex made a stats read discard concurrently encoded RTP.
// Membership alone takes the write lock; RTP still uses a nonblocking read.
static MEDIA_CHANNELS: std::sync::LazyLock<
    std::sync::RwLock<std::collections::HashMap<u64, MediaChannel>>,
> = std::sync::LazyLock::new(|| std::sync::RwLock::new(std::collections::HashMap::new()));

/// Monotonic channel-id source (never reuses 0, which the ABI reserves for
/// "error / invalid").
#[cfg(feature = "node-embedded")]
static MEDIA_NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// Outbound queue depth per media channel. Keep this bounded: media is a real-
/// time path, and a deep FIFO turns transient overload into stale audio/video.
/// Split audio/RTCP/unknown from VP8 RTP so a video keyframe burst cannot put
/// audio behind it. Queue-full is reported as loss to WebRTC; a later
/// keyframe/Opus PLC recovers without replaying an old tail.
///
/// Sizing (real-P2P freeze fix): the VIDEO queue must absorb one keyframe's
/// packet burst. The relay path assembles whole frames before queueing
/// (`RELAY_VIDEO_FRAME_QUEUE` frames × up to 512 packets), but the
/// direct/onion paths queue raw RTP packets — with the old 4-packet cap a
/// single VP8 keyframe (~25-50 MTU packets at 900 kbps) overflowed the queue
/// EVERY time it coincided with a stalled drain, dropping mid-frame packets.
/// Each drop corrupted the frame downstream (receiver froze until the next
/// keyframe, its jitter buffer inflating then flushing) and incremented
/// `tx_drops`, which the bitrate adapter treats as a bad sample — so the
/// ladder oscillated 900↔675 kbps, and every retune forced ANOTHER keyframe:
/// a self-sustaining freeze cycle on an otherwise clean LAN path. 64 packets
/// ≈ one large keyframe; the pacer upstream keeps standing depth near zero,
/// so this does not re-introduce a stale-media FIFO under real congestion.
#[cfg(feature = "node-embedded")]
const MEDIA_TX_HI_QUEUE: usize = 32;
#[cfg(feature = "node-embedded")]
const MEDIA_TX_VIDEO_QUEUE: usize = 64;

/// Max packets a direct-channel drain iteration sends under one sender lock.
/// Eight is roughly one small VP8 frame (or part of a keyframe): the former
/// 32-packet critical section emitted several frames as one IPC burst and was
/// visible on a physical P2P call as a smooth encoder cadence followed by
/// 75-335 ms arrival gaps. The queue still absorbs a complete keyframe, while
/// yielding between groups lets the embedded session writer and audio lane run.
/// There is no timer/prefill — a queued continuation is selected immediately.
#[cfg(feature = "node-embedded")]
const MEDIA_TX_BURST_MAX: usize = 8;

/// Sixteen frames absorb a keyframe drain plus roughly 500 ms of 30 fps camera
/// output. Four frames were only ~130 ms after the direct profile moved above
/// 20 fps: the relay queue then dropped whole VP8 inter-frames while draining a
/// keyframe, and the receiver froze until the next keyframe. Including the
/// frame currently being drained and the in-progress assembler, pathological
/// output remains bounded to ~3 MiB per channel. Ordinary 640x360 VP8 frames
/// are much smaller; the cap keeps malformed/self-buggy output from turning the
/// realtime path into an allocator sink. This is a capacity ceiling, not a
/// prefill target: the drain receives every complete frame immediately.
#[cfg(feature = "node-embedded")]
const RELAY_VIDEO_FRAME_QUEUE: usize = 16;
#[cfg(feature = "node-embedded")]
const RELAY_VIDEO_FRAME_MAX_PACKETS: usize = 512;
#[cfg(feature = "node-embedded")]
const RELAY_VIDEO_FRAME_MAX_BYTES: usize = 512 * 1024;
/// A complete relay video frame is already available here, so packet groups
/// can be encoded immediately without the 20 ms gather used for audio. Four
/// MTU-sized packets stay comfortably below the relay realtime-class ceiling
/// and preserve the existing audio-interleave cadence.
#[cfg(feature = "node-embedded")]
const RELAY_VIDEO_BATCH_MAX_PACKETS: usize = 4;
#[cfg(feature = "node-embedded")]
const RELAY_VIDEO_BATCH_BODY_MAX: usize = 7168;
#[cfg(feature = "node-embedded")]
const MEDIA_BATCHING_OFF: u8 = 0;
#[cfg(feature = "node-embedded")]
const MEDIA_BATCHING_LEGACY: u8 = 1;
#[cfg(feature = "node-embedded")]
const MEDIA_BATCHING_COMPACT_RELAY: u8 = 2;
/// Maximum plaintext media cell in compact relay mode. After the 36-byte
/// symmetric seal and fixed Delivery/session framing this remains below the
/// negotiated 1382-byte QUIC DATAGRAM ceiling, with margin for extensions.
#[cfg(feature = "node-embedded")]
const COMPACT_RELAY_MEDIA_CELL_MAX: usize = 1000;

#[cfg(feature = "node-embedded")]
#[derive(Default)]
struct RelayVideoFrameAssembler {
    discard_until_marker: bool,
    // The last original frame remains known after its marker/reset so a NACK
    // retransmission can be sent independently of the current frame. RTP
    // timestamps are serial numbers; ordinary wrap is not a backwards frame.
    newest_timestamp: Option<u32>,
    timestamp: Option<u32>,
    packets: Vec<Vec<u8>>,
    bytes: usize,
}

#[cfg(feature = "node-embedded")]
enum RelayVideoFramePush {
    Pending,
    Complete(Vec<Vec<u8>>),
    Dropped,
}

#[cfg(feature = "node-embedded")]
impl RelayVideoFrameAssembler {
    fn push(&mut self, packet: Vec<u8>) -> RelayVideoFramePush {
        if packet.len() < 8 || (packet[0] >> 6) != 2 {
            self.reset();
            return RelayVideoFramePush::Dropped;
        }
        let timestamp = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);
        if self.newest_timestamp.is_some_and(|newest| {
            (timestamp.wrapping_sub(newest) as i32) < 0
                || (timestamp == newest && self.timestamp.is_none() && !self.discard_until_marker)
        }) {
            // NACK repairs contain individual old RTP fragments, often without
            // the frame's marker. Waiting for the whole old frame swallows the
            // repair; replacing the current prefix also corrupts a new frame.
            // Keep the same bounded video queue/plane and send this work item
            // immediately. A repair marker must not end contention discard.
            if packet.len() > RELAY_VIDEO_FRAME_MAX_BYTES {
                return RelayVideoFramePush::Dropped;
            }
            return RelayVideoFramePush::Complete(vec![packet]);
        }
        self.newest_timestamp = Some(timestamp);
        if self.discard_until_marker {
            if packet[1] & 0x80 != 0 {
                self.discard_until_marker = false;
            }
            return RelayVideoFramePush::Dropped;
        }
        if self.timestamp.is_some_and(|current| current != timestamp) {
            // A new frame started before the previous marker arrived. Never
            // forward the orphan prefix: it cannot be decoded and only adds
            // latency ahead of the next complete frame.
            self.reset();
        }
        self.timestamp = Some(timestamp);
        let next_bytes = self.bytes.saturating_add(packet.len());
        if self.packets.len() >= RELAY_VIDEO_FRAME_MAX_PACKETS
            || next_bytes > RELAY_VIDEO_FRAME_MAX_BYTES
        {
            self.reset();
            return RelayVideoFramePush::Dropped;
        }
        let marker = packet[1] & 0x80 != 0;
        self.bytes = next_bytes;
        self.packets.push(packet);
        if !marker {
            return RelayVideoFramePush::Pending;
        }
        self.timestamp = None;
        self.bytes = 0;
        RelayVideoFramePush::Complete(std::mem::take(&mut self.packets))
    }

    fn discard_after_contention(&mut self) {
        self.reset();
        self.discard_until_marker = true;
    }

    fn reset(&mut self) {
        self.timestamp = None;
        self.packets.clear();
        self.bytes = 0;
    }
}

#[cfg(feature = "node-embedded")]
fn flush_media_batch_chunk(
    chunk: &mut Vec<Vec<u8>>,
    cells: &mut Vec<(Vec<u8>, usize)>,
    max_body: usize,
) {
    let packets = std::mem::take(chunk);
    if packets.len() < 2 {
        cells.extend(packets.into_iter().map(|packet| (packet, 1)));
        return;
    }
    if let Some(body) = media::encode_batch(&packets, max_body) {
        let mut cell = Vec::with_capacity(1 + body.len());
        cell.push(media::MEDIA_BATCH_MAGIC);
        cell.extend_from_slice(&body);
        cells.push((cell, packets.len()));
    } else {
        // Defensive fallback: never lose a frame because a future encoder
        // constraint changed. The packets are still sent in their RTP order.
        cells.extend(packets.into_iter().map(|packet| (packet, 1)));
    }
}

#[cfg(feature = "node-embedded")]
fn timed_media_cells(
    packets: Vec<QueuedMediaPacket>,
    batching: bool,
    max_body: usize,
    max_packets: usize,
) -> Vec<QueuedMediaPacket> {
    let (payloads, deadlines): (Vec<_>, Vec<_>) = packets
        .into_iter()
        .map(|packet| (packet.payload, packet.deadline))
        .unzip();
    let mut deadlines = deadlines.into_iter();
    let cells = if batching {
        media_batched_cells_with_counts(payloads, max_body, max_packets)
    } else {
        payloads.into_iter().map(|payload| (payload, 1)).collect()
    };
    cells
        .into_iter()
        .map(|(payload, count)| QueuedMediaPacket {
            payload,
            deadline: deadlines
                .by_ref()
                .take(count)
                .min()
                .expect("cell retains its packets' deadlines"),
        })
        .collect()
}

#[cfg(all(test, feature = "node-embedded"))]
fn media_batched_cells(frame: Vec<Vec<u8>>, max_body: usize, max_packets: usize) -> Vec<Vec<u8>> {
    media_batched_cells_with_counts(frame, max_body, max_packets)
        .into_iter()
        .map(|(cell, _)| cell)
        .collect()
}

/// Convert one complete VP8 frame into relay wire cells. This is a capacity
/// optimization, not a gather buffer: the frame is emitted immediately. Old
/// peers get the original one-RTP-packet-per-cell representation.
#[cfg(all(test, feature = "node-embedded"))]
fn media_wire_cells(frame: Vec<Vec<u8>>, batching: bool) -> Vec<Vec<u8>> {
    if !batching {
        return frame;
    }
    media_batched_cells(
        frame,
        RELAY_VIDEO_BATCH_BODY_MAX,
        RELAY_VIDEO_BATCH_MAX_PACKETS,
    )
}

#[cfg(feature = "node-embedded")]
fn media_batched_cells_with_counts(
    frame: Vec<Vec<u8>>,
    max_body: usize,
    max_packets: usize,
) -> Vec<(Vec<u8>, usize)> {
    let mut cells = Vec::with_capacity(frame.len().div_ceil(max_packets));
    let mut chunk = Vec::with_capacity(max_packets);
    let mut body_bytes = 2usize; // batch packet-count prefix
    for packet in frame {
        let encoded_bytes = 2usize.saturating_add(packet.len());
        if encoded_bytes.saturating_add(2) > max_body {
            flush_media_batch_chunk(&mut chunk, &mut cells, max_body);
            cells.push((packet, 1));
            body_bytes = 2;
            continue;
        }
        if !chunk.is_empty()
            && (chunk
                .first()
                .is_some_and(|first| media_is_vp8_rtp(first) != media_is_vp8_rtp(&packet))
                || chunk.len() >= max_packets
                || body_bytes.saturating_add(encoded_bytes) > max_body)
        {
            flush_media_batch_chunk(&mut chunk, &mut cells, max_body);
            body_bytes = 2;
        }
        body_bytes = body_bytes.saturating_add(encoded_bytes);
        chunk.push(packet);
    }
    flush_media_batch_chunk(&mut chunk, &mut cells, max_body);
    cells
}

#[cfg(feature = "node-embedded")]
pub(crate) fn dispatch_route_control(
    peer: [u8; 32],
    chan: u64,
    cipher: &Arc<media::MediaCipher>,
    body: &[u8],
) {
    let map = MEDIA_CHANNELS.read().unwrap_or_else(|p| p.into_inner());
    if let Some(ch) = map.get(&chan)
        && ch.peer == peer
        && Arc::ptr_eq(&ch.cipher, cipher)
        && let Some(routes) = &ch.routes
    {
        routes.accept_control(body);
    }
}
