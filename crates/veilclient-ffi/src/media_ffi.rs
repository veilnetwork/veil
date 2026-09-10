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
fn media_is_vp8_rtp(payload: &[u8]) -> bool {
    if payload.len() < 2 || (payload[0] >> 6) != 2 {
        return false;
    }
    // rtcp-mux RTCP packet types occupy the 64..=95 range. Video RTP is the
    // fixed VP8 payload type configured by veil_media_engine.cc.
    (payload[1] & 0x7f) == 96
}

#[cfg(all(test, feature = "node-embedded"))]
mod media_priority_tests;

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
    let cipher_task = Arc::clone(&cipher);
    let hub = match ensure_anon_hub(&handle_live.bundle, &handle_live.anon_hub) {
        Ok(h) => h,
        Err(e) => {
            unsafe { write_err(err_out, format!("media open: {e}")) };
            return 0;
        }
    };
    let (tx_hi, mut rx_hi) = mpsc::channel::<Vec<u8>>(MEDIA_TX_HI_QUEUE);
    let (tx_video, mut rx_video) = mpsc::channel::<Vec<u8>>(MEDIA_TX_VIDEO_QUEUE);
    let (repair_tx, mut repair_rx) = mpsc::channel::<()>(1);
    let send_hub = hub.clone();
    // One drain task per channel: warm the circuit, then pump queued datagrams
    // into the lossy send. `send_datagram` itself drops on QueueFull/no-route,
    // so a wedged circuit degrades to silent loss, never to a stall.
    //
    // Self-heal a stale route: the initial `media_open_channel` resolves the
    // peer's rendezvous ONCE. If the channel is opened before the peer has
    // (re)published a reachable rendezvous ad — e.g. a call whose callee is a
    // just-woken NAT'd phone that registers seconds/minutes later — that resolve
    // finds stale/absent ads, the circuit points nowhere, and EVERY datagram is
    // silently dropped for the whole call (device-observed: desktop->phone media
    // 0% while phone->desktop was fine). A run of no-route drops is the signal to
    // re-resolve: re-call `media_open_channel` (ensure_outbound_opening rebuilds
    // with a fresh resolve past its own dedup window), so we pick the peer up the
    // moment it becomes reachable instead of staying dark. Healthy sends return
    // true and reset the counter, so a flowing call pays nothing.
    const MEDIA_REWARM_EVERY_DROPS: u32 = 20;
    let task = handle_live.bundle.runtime.spawn(async move {
        send_hub.media_open_channel(peer).await;
        let mut consecutive_drops: u32 = 0;
        let mut pending: Option<Vec<u8>> = None;
        loop {
            let first = if let Some(pkt) = pending.take() {
                pkt
            } else {
                tokio::select! {
                    biased;
                    Some(()) = repair_rx.recv() => {
                        // The request is end-to-end evidence from the peer,
                        // unlike a successful enqueue to our first hop. Force
                        // a fresh rendezvous resolve/pool open. The opener is
                        // make-before-break and preserves routes carrying live
                        // reliable streams, so repairing a call cannot tear a
                        // concurrent file transfer down.
                        send_hub.media_open_channel(peer).await;
                        continue;
                    }
                    Some(pkt) = rx_hi.recv() => pkt,
                    Some(pkt) = rx_video.recv() => pkt,
                    else => break,
                }
            };
            // WebRTC emits a video frame as a tight RTP burst. Drain packets
            // already queued at this instant into one padded onion cell; never
            // wait for another packet, so batching adds no timer latency.
            const MAX_BATCH_PACKETS: usize = 12;
            let mut body_len = 2 + 2 + first.len();
            let mut packets = vec![first];
            while packets.len() < MAX_BATCH_PACKETS {
                // The first packet above remains biased toward audio/RTCP, but
                // once that real-time slot is secured, drain video first. Opus
                // is effectively continuous; preferring `rx_hi` here as well
                // could starve every VP8 keyframe while audio kept flowing.
                // A batch therefore carries prompt audio plus as much of the
                // already-queued video burst as fits in the same padded cell.
                let next = rx_video.try_recv().or_else(|_| rx_hi.try_recv());
                let Ok(pkt) = next else {
                    break;
                };
                let next_len = body_len.saturating_add(2 + pkt.len());
                if next_len > anon_stream::media_batch_body_max() {
                    pending = Some(pkt);
                    break;
                }
                body_len = next_len;
                packets.push(pkt);
            }
            // Fold to ONE cell and seal it. A cell that will not seal (the
            // sequence space is exhausted) is dropped, never sent in the
            // clear — the splice relay reads whatever goes down this circuit.
            // Not a route problem either, so it must not arm the re-warm.
            let Some(cell) = media::media_cell(packets, anon_stream::media_batch_body_max()) else {
                continue;
            };
            let Some(sealed) = cipher_task.seal(&cell) else {
                continue;
            };
            // The plaintext is MOVED out of scope the moment it is sealed. No
            // unit test can reach this drain (it needs a live embedded node),
            // so the guarantee has to be one the compiler makes: a future edit
            // that sends `cell` instead of `sealed` does not build.
            drop(cell);
            if send_hub.media_send_datagram(peer, &sealed).await {
                consecutive_drops = 0;
            } else {
                consecutive_drops += 1;
                if consecutive_drops % MEDIA_REWARM_EVERY_DROPS == 1 {
                    send_hub.media_open_channel(peer).await;
                }
            }
        }
    });
    let id = MEDIA_NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    MEDIA_CHANNELS
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(
            id,
            MediaChannel {
                tx_hi,
                video: MediaVideoIngress::Packets(tx_video),
                repair_tx: Some(repair_tx),
                peer,
                task,
                batching: None,
                cipher,
                relay_stats: None,
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
    let cipher_task = Arc::clone(&cipher);

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

    let (tx_hi, mut rx_hi) = mpsc::channel::<Vec<u8>>(MEDIA_TX_HI_QUEUE);
    let (tx_video, mut rx_video) = mpsc::channel::<Vec<u8>>(MEDIA_TX_VIDEO_QUEUE);
    let sender = Arc::clone(&app_ref.sender);
    let batching = Arc::new(std::sync::atomic::AtomicU8::new(MEDIA_BATCHING_OFF));
    let batching_task = Arc::clone(&batching);
    let task = app_ref.bundle.runtime.spawn(async move {
        let started = std::time::Instant::now();
        let mut transport_seq = 0u32;
        let mut prefer_video = false;
        loop {
            let pkt = if prefer_video {
                match rx_video.try_recv() {
                    Ok(pkt) => pkt,
                    Err(_) => tokio::select! {
                        biased;
                        Some(pkt) = rx_hi.recv() => pkt,
                        Some(pkt) = rx_video.recv() => pkt,
                        else => break,
                    },
                }
            } else {
                tokio::select! {
                    biased;
                    Some(pkt) = rx_hi.recv() => pkt,
                    Some(pkt) = rx_video.recv() => pkt,
                    else => break,
                }
            };
            // Audio/RTCP wins the first contested slot, then one queued VP8
            // packet gets the next slot. Without this bounded alternation the
            // continuously-ready Opus queue can starve video indefinitely.
            prefer_video = !media_is_vp8_rtp(&pkt);
            // Greedy burst drain: absorb whatever queued behind the first
            // packet (audio first) and send it back-to-back under ONE sender
            // lock. Sending exactly one packet per awaited IPC write capped
            // the drain rate at the write latency, which is what let a
            // keyframe burst overflow the bounded queue (see
            // MEDIA_TX_VIDEO_QUEUE) while the wire itself was nowhere near
            // saturated.
            let mut burst = vec![pkt];
            while burst.len() < MEDIA_TX_BURST_MAX {
                if let Ok(p) = rx_hi.try_recv() {
                    burst.push(p);
                    continue;
                }
                match rx_video.try_recv() {
                    Ok(p) => burst.push(p),
                    Err(_) => break,
                }
            }
            // The packets above are already available NOW; encode them into
            // at most two MEDIA_BATCH cells instead of making up to eight
            // sequential IPC writes. There is no gather timer and therefore
            // no added playout latency. This removes the periodic writer-lock
            // stalls that produced 75-800 ms arrival gaps on an otherwise
            // loss-free direct call. The host enables this only for a peer
            // whose call protocol version advertises batch decoding.
            let cells = media_wire_cells(
                burst,
                batching_task.load(std::sync::atomic::Ordering::Relaxed) != MEDIA_BATCHING_OFF,
            );
            let guard = sender.lock().await;
            let Some(sender) = guard.as_ref() else {
                break;
            };
            for pkt in cells {
                // Read the realtime-class hints off the PLAINTEXT, before the
                // seal hides them. They ride the RT_DATA header exactly as
                // before — the local daemon needs them to class the frame —
                // so sealing costs no scheduling quality and leaks nothing the
                // header did not already carry.
                let (marker, payload_type) = if pkt.len() >= 2 && (pkt[0] >> 6) == 2 {
                    ((pkt[1] >> 7) & 1, u32::from(pkt[1] & 0x7f))
                } else {
                    (0, 0)
                };
                // Unsealable cell → drop it. There is no cleartext fallback.
                let Some(sealed) = cipher_task.seal(&pkt) else {
                    continue;
                };
                // Plaintext MOVED out of scope: sending `pkt` below would not
                // compile. See the onion drain for why this is a `drop` and not
                // a comment.
                drop(pkt);
                let timestamp_us = started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
                let _ = sender
                    .send_rt_data(
                        peer,
                        peer_app,
                        peer_endpoint_id,
                        transport_seq,
                        timestamp_us,
                        marker,
                        payload_type,
                        sealed.as_bytes(),
                    )
                    .await;
                transport_seq = transport_seq.wrapping_add(1);
            }
        }
    });
    let id = MEDIA_NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    MEDIA_CHANNELS
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(
            id,
            MediaChannel {
                tx_hi,
                video: MediaVideoIngress::Packets(tx_video),
                repair_tx: None,
                peer,
                task,
                batching: Some(batching),
                cipher,
                relay_stats: None,
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

    let (tx_hi, mut rx_hi) = mpsc::channel::<Vec<u8>>(MEDIA_TX_HI_QUEUE);
    let (tx_video_frames, mut rx_video_frames) =
        mpsc::channel::<RelayVideoFrame>(RELAY_VIDEO_FRAME_QUEUE);
    let sender = Arc::clone(&app_ref.sender);
    let batching = Arc::new(std::sync::atomic::AtomicU8::new(MEDIA_BATCHING_OFF));
    let batching_task = Arc::clone(&batching);
    let cipher_task = Arc::clone(&cipher);
    let relay_stats = Arc::new(RelayMediaStats::default());
    let relay_stats_task = Arc::clone(&relay_stats);
    let task = app_ref.bundle.runtime.spawn(async move {
        let mut prefer_video = false;
        let mut pending_high = None;
        loop {
            enum Work {
                High(Vec<u8>),
                VideoFrame(RelayVideoFrame),
            }
            let work = if let Some(pkt) = pending_high.take() {
                Work::High(pkt)
            } else if prefer_video {
                match rx_video_frames.try_recv() {
                    Ok(frame) => Work::VideoFrame(frame),
                    Err(_) => tokio::select! {
                        biased;
                        Some(pkt) = rx_hi.recv() => Work::High(pkt),
                        Some(frame) = rx_video_frames.recv() => Work::VideoFrame(frame),
                        else => break,
                    },
                }
            } else {
                tokio::select! {
                    biased;
                    Some(pkt) = rx_hi.recv() => Work::High(pkt),
                    Some(frame) = rx_video_frames.recv() => Work::VideoFrame(frame),
                    else => break,
                }
            };
            prefer_video = matches!(work, Work::High(_));
            // The relay path pays a full E2E envelope + cell padding PER
            // datagram — ~2 KiB on the wire for an ~100 B Opus packet, a
            // device-measured ~24× inflation that saturated a last-mile link
            // and stalled the whole ordered stream (ROADMAP section S). When
            // the peer understands MEDIA_BATCH_MAGIC (host-gated by call
            // protocol version), legacy v2 gathers audio/RTCP packets within
            // one frame interval and ships one envelope. Compact v3 no longer
            // pays per-cell KEM overhead, so it coalesces only packets already
            // queued and never adds a gather delay.
            let batching_mode = batching_task.load(std::sync::atomic::Ordering::Relaxed);
            let work = match work {
                Work::High(first) if batching_mode != MEDIA_BATCHING_OFF => {
                    const RELAY_BATCH_MAX_PKTS: usize = 6;
                    // GATHER byte budget: stop pulling once the running body
                    // estimate crosses this. The last packet may overshoot,
                    // but even a full MTU media datagram (~1.5 KiB) on top of
                    // this budget stays well under the ENCODE ceiling below —
                    // so the gathered set ALWAYS encodes and no packet that
                    // was already dequeued is ever dropped.
                    let relay_batch_soft_bytes = if batching_mode == MEDIA_BATCHING_COMPACT_RELAY {
                        COMPACT_RELAY_MEDIA_CELL_MAX - 1
                    } else {
                        3072
                    };
                    // ENCODE ceiling: comfortably above the gather budget +
                    // one overshoot packet, and still under the relay's 8 KiB
                    // REALTIME classing cap (post-envelope) so a batched cell
                    // never demotes to Interactive.
                    let relay_batch_body_max = if batching_mode == MEDIA_BATCHING_COMPACT_RELAY {
                        COMPACT_RELAY_MEDIA_CELL_MAX - 1
                    } else {
                        7168
                    };
                    // Running estimate of encode_batch's body: 2-byte count
                    // header + per packet a 2-byte length prefix + payload.
                    let mut body_est = 2 + 2 + first.len();
                    let mut pkts = vec![first];
                    if batching_mode == MEDIA_BATCHING_COMPACT_RELAY {
                        // Compact sealing removed the per-packet KEM cost, so
                        // never hold the first Opus packet waiting for another.
                        // Coalesce only packets already queued at this instant.
                        while pkts.len() < RELAY_BATCH_MAX_PKTS && body_est < relay_batch_soft_bytes
                        {
                            let Ok(p) = rx_hi.try_recv() else {
                                break;
                            };
                            let next_est = body_est.saturating_add(2 + p.len());
                            if next_est > relay_batch_body_max {
                                pending_high = Some(p);
                                break;
                            }
                            body_est = next_est;
                            pkts.push(p);
                        }
                    } else {
                        let deadline =
                            tokio::time::Instant::now() + std::time::Duration::from_millis(20);
                        while pkts.len() < RELAY_BATCH_MAX_PKTS && body_est < relay_batch_soft_bytes
                        {
                            tokio::select! {
                                biased;
                                more = rx_hi.recv() => match more {
                                    Some(p) => {
                                        let next_est = body_est.saturating_add(2 + p.len());
                                        if next_est > relay_batch_body_max {
                                            pending_high = Some(p);
                                            break;
                                        }
                                        body_est = next_est;
                                        pkts.push(p);
                                    }
                                    None => break,
                                },
                                _ = tokio::time::sleep_until(deadline) => break,
                            }
                        }
                    }
                    Work::High(if pkts.len() == 1 {
                        pkts.pop().expect("one packet")
                    } else if let Some(body) = media::encode_batch(&pkts, relay_batch_body_max) {
                        let mut cell = Vec::with_capacity(1 + body.len());
                        cell.push(media::MEDIA_BATCH_MAGIC);
                        cell.extend_from_slice(&body);
                        cell
                    } else {
                        // Unreachable in practice: the gather budget guarantees
                        // the set fits RELAY_BATCH_BODY_MAX. Defensive only — a
                        // degenerate burst of maximally-oversized datagrams
                        // sends the first whole rather than a malformed cell.
                        pkts.swap_remove(0)
                    })
                }
                other => other,
            };
            let lock_started = std::time::Instant::now();
            let guard = sender.lock().await;
            relay_stats_task.observe_sender_lock(lock_started.elapsed());
            let Some(sender) = guard.as_ref() else {
                break;
            };
            match work {
                Work::High(pkt) => {
                    // No unsealed fallback. The ML-KEM-per-envelope path this
                    // used to fall back to hid the bytes from the relay but
                    // proved nothing about who wrote them — anyone may encrypt
                    // to a public key — so falling back was a downgrade, not a
                    // safety net. A cell that will not seal is dropped.
                    let Some(sealed) = cipher_task.seal(&pkt) else {
                        continue;
                    };
                    drop(pkt); // plaintext moved out of scope; see the onion drain
                    let ipc_started = std::time::Instant::now();
                    let result = sender
                        .send_relay_media_sealed_owned(
                            peer,
                            peer_app,
                            peer_endpoint_id,
                            sealed.into_vec(),
                        )
                        .await;
                    let failed = result.is_err();
                    relay_stats_task.observe_ipc_cell(ipc_started.elapsed(), failed);
                }
                Work::VideoFrame(frame) => {
                    relay_stats_task.start_frame(frame.enqueued_at.elapsed());
                    let frame_ipc_started = std::time::Instant::now();
                    // The frame is complete, so batching adds no gather delay:
                    // it only removes repeated relay envelopes and lets the
                    // receiver assemble the frame with less arrival jitter.
                    let batching_enabled = batching_task.load(std::sync::atomic::Ordering::Relaxed)
                        == MEDIA_BATCHING_LEGACY;
                    for cell in media_wire_cells(frame.packets, batching_enabled) {
                        // One batch contains at most four video packets, so this
                        // preserves the former one-audio-slot-per-four cadence.
                        if let Some(sealed) = rx_hi
                            .try_recv()
                            .ok()
                            .and_then(|high| cipher_task.seal(&high))
                        {
                            let ipc_started = std::time::Instant::now();
                            let result = sender
                                .send_relay_media_sealed_owned(
                                    peer,
                                    peer_app,
                                    peer_endpoint_id,
                                    sealed.into_vec(),
                                )
                                .await;
                            let failed = result.is_err();
                            relay_stats_task.observe_ipc_cell(ipc_started.elapsed(), failed);
                        }
                        let Some(sealed) = cipher_task.seal(&cell) else {
                            continue;
                        };
                        drop(cell); // plaintext moved out of scope; see the onion drain
                        let ipc_started = std::time::Instant::now();
                        let result = sender
                            .send_relay_media_sealed_owned(
                                peer,
                                peer_app,
                                peer_endpoint_id,
                                sealed.into_vec(),
                            )
                            .await;
                        let failed = result.is_err();
                        relay_stats_task.observe_ipc_cell(ipc_started.elapsed(), failed);
                    }
                    relay_stats_task.observe_frame_ipc(frame_ipc_started.elapsed());
                }
            }
        }
    });
    let id = MEDIA_NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    MEDIA_CHANNELS
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(
            id,
            MediaChannel {
                tx_hi,
                video: MediaVideoIngress::RelayFrames {
                    tx: tx_video_frames,
                    assembler: RelayVideoFrameAssembler::default(),
                    stats: Arc::clone(&relay_stats),
                },
                repair_tx: None,
                peer,
                task,
                batching: Some(batching),
                cipher,
                relay_stats: Some(relay_stats),
            },
        );
    id
}

/// Enqueue one media datagram (RTP/RTCP) on `chan`. NON-BLOCKING: returns 0 if
/// queued, 1 if dropped (queue full / channel closing) — the caller's real-time
/// media thread must never block. Returns -1 on a NULL/zero-length payload or an
/// unknown `chan`.
#[cfg(feature = "node-embedded")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_media_send_datagram(chan: u64, ptr: *const u8, len: size_t) -> c_int {
    if chan == 0 || ptr.is_null() || len == 0 {
        return -1;
    }
    let payload = unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec();
    let mut map = MEDIA_CHANNELS.lock().unwrap_or_else(|p| p.into_inner());
    let Some(ch) = map.get_mut(&chan) else {
        return -1;
    };
    if !media_is_vp8_rtp(&payload) {
        return match ch.tx_hi.try_send(payload) {
            Ok(()) => 0,
            Err(mpsc::error::TrySendError::Full(_)) => 1,
            Err(mpsc::error::TrySendError::Closed(_)) => -1,
        };
    }
    match &mut ch.video {
        MediaVideoIngress::Packets(tx) => match tx.try_send(payload) {
            Ok(()) => 0,
            Err(mpsc::error::TrySendError::Full(_)) => 1,
            Err(mpsc::error::TrySendError::Closed(_)) => -1,
        },
        MediaVideoIngress::RelayFrames {
            tx,
            assembler,
            stats,
        } => match assembler.push(payload) {
            RelayVideoFramePush::Pending => 0,
            RelayVideoFramePush::Dropped => 1,
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
                        1
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        stats.undo_enqueue_frame();
                        -1
                    }
                }
            }
        },
    }
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
    let map = MEDIA_CHANNELS.lock().unwrap_or_else(|p| p.into_inner());
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
    let map = MEDIA_CHANNELS.lock().unwrap_or_else(|p| p.into_inner());
    let Some(repair_tx) = map.get(&chan).and_then(|ch| ch.repair_tx.as_ref()) else {
        return -1;
    };
    match repair_tx.try_send(()) {
        Ok(()) => 0,
        Err(mpsc::error::TrySendError::Full(_)) => 1,
        Err(mpsc::error::TrySendError::Closed(_)) => -1,
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
    let map = MEDIA_CHANNELS.lock().unwrap_or_else(|p| p.into_inner());
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
/// once per inbound media datagram from `chan`'s peer, with the wire magic
/// already stripped. Replaces any prior callback; `cb == NULL` clears it.
/// Returns 0, or -1 on an unknown `chan`.
#[cfg(feature = "node-embedded")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_media_set_recv_callback(
    chan: u64,
    cb: Option<media::MediaRecvFn>,
    ctx: *mut c_void,
) -> c_int {
    let channel = {
        let map = MEDIA_CHANNELS.lock().unwrap_or_else(|p| p.into_inner());
        map.get(&chan).map(|ch| (ch.peer, Arc::clone(&ch.cipher)))
    };
    match (cb, channel) {
        (Some(cb), Some((peer, cipher))) => media::set_recv_callback(peer, chan, cb, ctx, cipher),
        // Registering on an unknown channel has nowhere to route — error out.
        (Some(_), None) => return -1,
        (None, Some((peer, _))) => media::clear_recv_callback(peer, chan),
        // Clearing must ALWAYS land: when the host closed the channel before
        // the engine unregistered, the peer key can't be resolved anymore, yet
        // leaving the stale registration would keep swallowing the peer's
        // inbound media into a stopped receiver. Sweep by owner chan instead.
        (None, None) => media::clear_recv_callback_by_chan(chan),
    }
    0
}

/// Close a media channel: stops the drain task, drops the outbound queue, and
/// clears the peer's recv callback. Idempotent (unknown `chan` is a no-op).
#[cfg(feature = "node-embedded")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_media_close_channel(chan: u64) {
    let ch = MEDIA_CHANNELS
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(&chan);
    if let Some(ch) = ch {
        // Dropping `ch.tx` already closes the queue (the drain loop ends), but
        // abort to reclaim the task promptly even if it is mid-await.
        ch.task.abort();
        media::clear_recv_callback(ch.peer, chan);
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
