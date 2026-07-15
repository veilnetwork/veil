//! Lossy media-datagram side channel over the anonymous onion circuit.
//!
//! Media (RTP/RTCP for calls) rides the SAME 2-hop circuit pool as the reliable
//! byte stream (see [`crate::anon_stream`]), but deliberately bypasses the
//! `Frame`/ARQ/pacing layer: each datagram is one circuit cell prefixed with
//! [`MEDIA_MAGIC`], and it is dropped rather than retransmitted on loss. That is
//! exactly what a real-time codec wants — PLC/FEC absorb the occasional gap and
//! a stale packet is worthless anyway.
//!
//! This module owns two things:
//!   * the wire magic byte, and
//!   * the inbound recv-callback registry that the circuit feed dispatches to.
//!
//! The outbound send path lives in
//! [`crate::anon_stream::CircuitCells::send_datagram`]; the per-channel FFI
//! (open / send / set-callback / close) lives in `lib.rs`.

use std::collections::HashMap;
use std::os::raw::c_void;
use std::sync::{LazyLock, Mutex};

/// First byte of every media cell. Distinct from
/// `veil_onion_stream::wire::PROTO_VER` (= 1), so a media cell is already an
/// invalid stream frame (`Frame::decode` → `None`) and the reliable demux would
/// reject it outright — media and stream coexist on one circuit with zero
/// collision, separated only by this byte.
pub const MEDIA_MAGIC: u8 = 0x4d; // 'M'

/// First byte of a media cell containing several RTP/RTCP datagrams. Keeping a
/// distinct top-level magic makes old receivers drop the unknown cell instead
/// of passing a batch envelope to WebRTC as if it were RTP.
pub const MEDIA_BATCH_MAGIC: u8 = 0x42; // 'B'

/// Encode multiple datagrams behind [`MEDIA_BATCH_MAGIC`]. Layout:
/// `[count u16][len u16][packet]...`. Returns `None` for an empty batch, an
/// oversized packet/count, or when the encoded body exceeds `max_bytes`.
pub fn encode_batch(packets: &[Vec<u8>], max_bytes: usize) -> Option<Vec<u8>> {
    let count = u16::try_from(packets.len()).ok()?;
    if count == 0 {
        return None;
    }
    let mut out = Vec::with_capacity(max_bytes.min(4096));
    out.extend_from_slice(&count.to_be_bytes());
    for packet in packets {
        let len = u16::try_from(packet.len()).ok()?;
        if out.len().checked_add(2 + packet.len())? > max_bytes {
            return None;
        }
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(packet);
    }
    Some(out)
}

/// C recv callback: `(ctx, ptr, len)`. Invoked from the circuit feed task once
/// per inbound media datagram, with the magic byte already stripped. It must not
/// block (it hands the packet straight to the media engine's RTP receiver).
pub type MediaRecvFn = extern "C" fn(*mut c_void, *const u8, usize);

struct RecvCb {
    cb: MediaRecvFn,
    /// A raw `*mut c_void` is neither `Send` nor `Sync`, so it cannot live in a
    /// `static`. Store it as a `usize` (which, alongside the `extern "C" fn`
    /// pointer, keeps `RecvCb` auto-`Send`) and cast it back at call time; the
    /// host guarantees the ctx outlives the channel (cleared on close).
    ctx: usize,
}

/// Inbound recv callbacks keyed by PEER node id. The circuit feed resolves the
/// sender node per cell, so dispatch is by-peer — one entry per open channel.
static RECV: LazyLock<Mutex<HashMap<[u8; 32], RecvCb>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Lightweight per-peer inbound datagram counter (delivered + dropped-for-no-
/// callback alike). A diagnostic stat that also lets a host poll receipt
/// without wiring a cross-thread recv callback — the Phase 2 two-node probe
/// reads it via `veil_media_recv_count`.
static RECV_COUNT: LazyLock<Mutex<HashMap<[u8; 32], u64>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Register (or replace) the recv callback for media datagrams arriving from
/// `peer`.
pub fn set_recv_callback(peer: [u8; 32], cb: MediaRecvFn, ctx: *mut c_void) {
    RECV.lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(peer, RecvCb { cb, ctx: ctx as usize });
}

/// Drop the recv callback for `peer` (channel close).
pub fn clear_recv_callback(peer: [u8; 32]) {
    RECV.lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(&peer);
}

/// Deliver one inbound media datagram from `peer` to its registered callback.
/// Called by `spawn_circuit_feed` after peeling [`MEDIA_MAGIC`]. A no-op (drop)
/// if no channel is open for `peer`. The registry lock is released BEFORE the
/// FFI call so a re-entrant set/clear from inside the callback cannot deadlock.
pub fn dispatch_inbound(peer: [u8; 32], payload: &[u8]) {
    {
        let mut counts = RECV_COUNT.lock().unwrap_or_else(|p| p.into_inner());
        *counts.entry(peer).or_insert(0) += 1;
    }
    let target = {
        let map = RECV.lock().unwrap_or_else(|p| p.into_inner());
        map.get(&peer).map(|c| (c.cb, c.ctx))
    };
    if let Some((cb, ctx)) = target {
        cb(ctx as *mut c_void, payload.as_ptr(), payload.len());
    }
}

/// Decode and deliver one batched media cell. The entire cell is dropped on
/// malformed length/count data; partial delivery would make corruption depend
/// on packet position and complicate loss accounting.
pub fn dispatch_inbound_batch(peer: [u8; 32], body: &[u8]) {
    if body.len() < 2 {
        return;
    }
    let count = u16::from_be_bytes([body[0], body[1]]) as usize;
    if count == 0 || count > 64 {
        return;
    }
    let mut offset = 2usize;
    let mut packets = Vec::with_capacity(count);
    for _ in 0..count {
        let Some(len_end) = offset.checked_add(2) else {
            return;
        };
        if len_end > body.len() {
            return;
        }
        let len = u16::from_be_bytes([body[offset], body[offset + 1]]) as usize;
        offset = len_end;
        let Some(end) = offset.checked_add(len) else {
            return;
        };
        if len == 0 || end > body.len() {
            return;
        }
        packets.push(&body[offset..end]);
        offset = end;
    }
    if offset != body.len() {
        return;
    }
    for packet in packets {
        dispatch_inbound(peer, packet);
    }
}

/// Number of inbound media datagrams received from `peer` since process start.
/// The all-zero peer is a diagnostic wildcard: it returns the GRAND TOTAL across
/// every peer (useful when the sender's node id isn't yet known to the receiver).
pub fn recv_count(peer: [u8; 32]) -> u64 {
    let counts = RECV_COUNT.lock().unwrap_or_else(|p| p.into_inner());
    if peer == [0u8; 32] {
        return counts.values().sum();
    }
    counts.get(&peer).copied().unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static RX_CALLS: AtomicUsize = AtomicUsize::new(0);
    static RX_BYTES: AtomicUsize = AtomicUsize::new(0);
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    extern "C" fn record(_ctx: *mut c_void, _ptr: *const u8, len: usize) {
        RX_CALLS.fetch_add(1, Ordering::SeqCst);
        RX_BYTES.fetch_add(len, Ordering::SeqCst);
    }

    #[test]
    fn dispatch_routes_by_peer_and_honors_clear() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let peer_a = [1u8; 32];
        let peer_b = [2u8; 32];
        RX_CALLS.store(0, Ordering::SeqCst);
        RX_BYTES.store(0, Ordering::SeqCst);

        set_recv_callback(peer_a, record, std::ptr::null_mut());
        // Registered peer → delivered (magic already stripped by the caller).
        dispatch_inbound(peer_a, &[0u8; 100]);
        // Unregistered peer → dropped (no channel open for it).
        dispatch_inbound(peer_b, &[0u8; 100]);
        assert_eq!(RX_CALLS.load(Ordering::SeqCst), 1, "only peer_a delivers");
        assert_eq!(RX_BYTES.load(Ordering::SeqCst), 100, "full payload length");

        // After clear → dropped, no callback invoked.
        clear_recv_callback(peer_a);
        dispatch_inbound(peer_a, &[0u8; 50]);
        assert_eq!(RX_CALLS.load(Ordering::SeqCst), 1, "cleared peer is silent");
    }

    #[test]
    fn media_magic_is_not_a_stream_proto_ver() {
        // A media cell's first byte must never be mistaken for a stream frame,
        // so the inbound demux can split the two by that byte alone.
        assert_ne!(MEDIA_MAGIC, veil_onion_stream::wire::PROTO_VER);
        assert_ne!(MEDIA_BATCH_MAGIC, veil_onion_stream::wire::PROTO_VER);
        assert_ne!(MEDIA_BATCH_MAGIC, MEDIA_MAGIC);
    }

    #[test]
    fn batch_roundtrip_delivers_each_packet() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let peer = [3u8; 32];
        RX_CALLS.store(0, Ordering::SeqCst);
        RX_BYTES.store(0, Ordering::SeqCst);
        set_recv_callback(peer, record, std::ptr::null_mut());
        let packets = vec![vec![1u8; 120], vec![2u8; 130], vec![3u8; 140]];
        let encoded = encode_batch(&packets, 1024).unwrap();
        dispatch_inbound_batch(peer, &encoded);
        clear_recv_callback(peer);
        assert_eq!(RX_CALLS.load(Ordering::SeqCst), 3);
        assert_eq!(RX_BYTES.load(Ordering::SeqCst), 390);
    }

    #[test]
    fn malformed_batch_is_atomic_drop() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let peer = [4u8; 32];
        RX_CALLS.store(0, Ordering::SeqCst);
        set_recv_callback(peer, record, std::ptr::null_mut());
        let mut encoded = encode_batch(&[vec![1u8; 10], vec![2u8; 10]], 128).unwrap();
        encoded.pop();
        dispatch_inbound_batch(peer, &encoded);
        clear_recv_callback(peer);
        assert_eq!(RX_CALLS.load(Ordering::SeqCst), 0);
    }
}
