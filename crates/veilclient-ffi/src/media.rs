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

use std::collections::{HashMap, VecDeque};
use std::os::raw::c_void;
use std::sync::{Arc, LazyLock, Mutex};

use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use rand_core::{OsRng, RngCore};
use zeroize::{Zeroize, Zeroizing};

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

/// Symmetrically sealed relay-media cell. The same marker is validated by the
/// local IPC daemon before it permits the compact presealed delivery path.
pub const MEDIA_SEALED_MAGIC: [u8; 4] = *b"VME1";
const MEDIA_SEALED_HEADER_LEN: usize = 4 + 8 + 8; // magic + epoch salt + sequence
const MEDIA_SEALED_TAG_LEN: usize = 16;
const MEDIA_SEALED_MAX_EPOCHS: usize = 4;
const MEDIA_SEALED_KDF_CONTEXT: &str = "xveil/call-media/channel-epoch/v1";

fn media_nonce(sequence: u64) -> Nonce {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&sequence.to_be_bytes());
    nonce.into()
}

fn media_epoch_key(master: &[u8; 32], salt: u64) -> [u8; 32] {
    let mut material = [0u8; 40];
    material[..32].copy_from_slice(master);
    material[32..].copy_from_slice(&salt.to_be_bytes());
    let key = blake3::derive_key(MEDIA_SEALED_KDF_CONTEXT, &material);
    material.zeroize();
    key
}

#[derive(Default)]
struct MediaReplayWindow {
    highest: u64,
    bitmap: u128,
}

impl MediaReplayWindow {
    fn accepts(&self, sequence: u64) -> bool {
        if sequence == 0 {
            return false;
        }
        if sequence > self.highest {
            return true;
        }
        let delta = self.highest - sequence;
        delta < u128::BITS as u64 && self.bitmap & (1u128 << delta) == 0
    }

    fn commit(&mut self, sequence: u64) {
        if sequence > self.highest {
            let shift = sequence - self.highest;
            self.bitmap = if shift >= u128::BITS as u64 {
                1
            } else {
                (self.bitmap << shift) | 1
            };
            self.highest = sequence;
        } else {
            self.bitmap |= 1u128 << (self.highest - sequence);
        }
    }
}

struct MediaCipherTx {
    cipher: ChaCha20Poly1305,
    salt: u64,
    next_sequence: u64,
}

impl MediaCipherTx {
    fn new(master: &[u8; 32]) -> Self {
        let mut rng = OsRng;
        let mut salt = rng.next_u64();
        if salt == 0 {
            salt = 1;
        }
        let mut key = media_epoch_key(master, salt);
        let cipher = ChaCha20Poly1305::new((&key).into());
        key.zeroize();
        Self {
            cipher,
            salt,
            next_sequence: 1,
        }
    }

    fn seal(&mut self, plaintext: &[u8]) -> Option<Vec<u8>> {
        if plaintext.is_empty() {
            return None;
        }
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.checked_add(1)?;
        let mut header = [0u8; MEDIA_SEALED_HEADER_LEN];
        header[..4].copy_from_slice(&MEDIA_SEALED_MAGIC);
        header[4..12].copy_from_slice(&self.salt.to_be_bytes());
        header[12..20].copy_from_slice(&sequence.to_be_bytes());
        let ciphertext = self
            .cipher
            .encrypt(
                &media_nonce(sequence),
                Payload {
                    msg: plaintext,
                    aad: &header,
                },
            )
            .ok()?;
        let mut sealed = Vec::with_capacity(header.len() + ciphertext.len());
        sealed.extend_from_slice(&header);
        sealed.extend_from_slice(&ciphertext);
        Some(sealed)
    }
}

struct MediaRxEpoch {
    salt: u64,
    cipher: ChaCha20Poly1305,
    replay: MediaReplayWindow,
}

struct MediaCipherRx {
    master: Zeroizing<[u8; 32]>,
    epochs: VecDeque<MediaRxEpoch>,
}

impl MediaCipherRx {
    fn new(master: &[u8; 32]) -> Self {
        Self {
            master: Zeroizing::new(*master),
            epochs: VecDeque::new(),
        }
    }

    fn open(&mut self, sealed: &[u8]) -> Option<Vec<u8>> {
        if sealed.len() <= MEDIA_SEALED_HEADER_LEN + MEDIA_SEALED_TAG_LEN
            || !sealed.starts_with(&MEDIA_SEALED_MAGIC)
        {
            return None;
        }
        let salt = u64::from_be_bytes(sealed[4..12].try_into().ok()?);
        let sequence = u64::from_be_bytes(sealed[12..20].try_into().ok()?);
        if salt == 0 || sequence == 0 {
            return None;
        }
        if let Some(epoch_index) = self.epochs.iter().position(|e| e.salt == salt) {
            if epoch_index != 0 {
                let epoch = self.epochs.remove(epoch_index)?;
                self.epochs.push_front(epoch);
            }
            let epoch = self.epochs.front_mut()?;
            if !epoch.replay.accepts(sequence) {
                return None;
            }
            let plaintext = epoch
                .cipher
                .decrypt(
                    &media_nonce(sequence),
                    Payload {
                        msg: &sealed[MEDIA_SEALED_HEADER_LEN..],
                        aad: &sealed[..MEDIA_SEALED_HEADER_LEN],
                    },
                )
                .ok()?;
            epoch.replay.commit(sequence);
            return Some(plaintext);
        }

        // Authenticate a new epoch before it consumes one of the bounded RX
        // slots. Otherwise unauthenticated random salts could evict every live
        // epoch without knowing the media key.
        let mut key = media_epoch_key(&self.master, salt);
        let cipher = ChaCha20Poly1305::new((&key).into());
        key.zeroize();
        let plaintext = cipher
            .decrypt(
                &media_nonce(sequence),
                Payload {
                    msg: &sealed[MEDIA_SEALED_HEADER_LEN..],
                    aad: &sealed[..MEDIA_SEALED_HEADER_LEN],
                },
            )
            .ok()?;
        let mut replay = MediaReplayWindow::default();
        replay.commit(sequence);
        if self.epochs.len() >= MEDIA_SEALED_MAX_EPOCHS {
            self.epochs.pop_back();
        }
        self.epochs.push_front(MediaRxEpoch {
            salt,
            cipher,
            replay,
        });
        Some(plaintext)
    }
}

/// Per-channel directional call-media cipher. A fresh random epoch salt is
/// mixed into the TX sub-key, so rebuilding a route during the same call can
/// safely restart its sequence at one without nonce reuse. RX retains only a
/// tiny bounded set of recent epochs for make-before-break overlap.
#[derive(Default)]
pub(crate) struct MediaCipher {
    tx: Mutex<Option<MediaCipherTx>>,
    rx: Mutex<Option<MediaCipherRx>>,
}

impl MediaCipher {
    pub(crate) fn configure(&self, mut tx_key: [u8; 32], mut rx_key: [u8; 32]) {
        let tx = MediaCipherTx::new(&tx_key);
        let rx = MediaCipherRx::new(&rx_key);
        tx_key.zeroize();
        rx_key.zeroize();
        *self.tx.lock().unwrap_or_else(|p| p.into_inner()) = Some(tx);
        *self.rx.lock().unwrap_or_else(|p| p.into_inner()) = Some(rx);
    }

    pub(crate) fn enabled(&self) -> bool {
        self.tx.lock().unwrap_or_else(|p| p.into_inner()).is_some()
    }

    pub(crate) fn seal(&self, plaintext: &[u8]) -> Option<Vec<u8>> {
        self.tx
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_mut()?
            .seal(plaintext)
    }

    fn open(&self, sealed: &[u8]) -> Option<Vec<u8>> {
        self.rx
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_mut()?
            .open(sealed)
    }
}

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

/// Debug-only breadcrumb file for the registry lifecycle. Media loss between
/// the authenticated receiver and the engine callback is otherwise invisible
/// (the send path keeps succeeding); debug builds trace registration and the
/// first dispatch hits/misses per peer so a stand can attribute a dead leg.
/// Compiled out of release builds entirely.
#[cfg(debug_assertions)]
pub(crate) fn diag(msg: std::fmt::Arguments<'_>) {
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("/tmp/veil_ffi_media_diag.log")
    {
        let _ = writeln!(f, "{msg}");
    }
}

#[cfg(not(debug_assertions))]
pub(crate) fn diag(_msg: std::fmt::Arguments<'_>) {}

struct RecvCb {
    cb: MediaRecvFn,
    /// A raw `*mut c_void` is neither `Send` nor `Sync`, so it cannot live in a
    /// `static`. Store it as a `usize` (which, alongside the `extern "C" fn`
    /// pointer, keeps `RecvCb` auto-`Send`) and cast it back at call time; the
    /// host guarantees the ctx outlives the channel (cleared on close).
    ctx: usize,
    /// Channel that owns this registration. A call bring-up can open several
    /// channels to the SAME peer back to back (failed direct attempt, P2P →
    /// relay switch, session rebuild); a straggling close of an OLD channel
    /// must not wipe the LIVE channel's callback, or the inbound leg dies
    /// silently for the rest of the call (device-observed: phone→desktop
    /// media dead while the node kept receiving every packet).
    chan: u64,
    /// Datagrams delivered THROUGH this registration (per-registration, unlike
    /// the process-lifetime HITS total). Logged on clear/replace so a debug
    /// trace can tell "the window delivered N packets into the engine" from
    /// "the window was registered yet delivered nothing" — the discriminator
    /// between a registry-side and an engine-side silent drop.
    hits: u64,
    /// Optional per-call E2E media cipher. Disabled channels retain the legacy
    /// ML-KEM-per-envelope/direct/onion ingress unchanged.
    cipher: Arc<MediaCipher>,
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
pub fn set_recv_callback(
    peer: [u8; 32],
    chan: u64,
    cb: MediaRecvFn,
    ctx: *mut c_void,
    cipher: Arc<MediaCipher>,
) {
    let replaced = RECV.lock().unwrap_or_else(|p| p.into_inner()).insert(
        peer,
        RecvCb {
            cb,
            ctx: ctx as usize,
            chan,
            hits: 0,
            cipher,
        },
    );
    diag(format_args!(
        "set_recv_callback peer={:02x}{:02x}{:02x}{:02x} chan={chan} replaces={}",
        peer[0],
        peer[1],
        peer[2],
        peer[3],
        replaced.map_or_else(
            || "none".to_owned(),
            |old| format!("chan{}(hits={})", old.chan, old.hits)
        )
    ));
}

/// Drop the recv callback for `peer` — but only when `chan` still owns it. A
/// newer channel to the same peer may have replaced the registration; its
/// callback must survive the old channel's teardown.
pub fn clear_recv_callback(peer: [u8; 32], chan: u64) {
    let mut map = RECV.lock().unwrap_or_else(|p| p.into_inner());
    let owned = map.get(&peer).is_some_and(|c| c.chan == chan);
    let hits = map.get(&peer).map_or(0, |c| c.hits);
    diag(format_args!(
        "clear_recv_callback peer={:02x}{:02x}{:02x}{:02x} chan={chan} owned={owned} hits={hits}",
        peer[0], peer[1], peer[2], peer[3]
    ));
    if owned {
        map.remove(&peer);
    }
}

/// Remove any registration owned by `chan`, regardless of peer key. Fallback
/// for the host clearing a callback AFTER it already closed the channel: the
/// normal clear resolves peer via the channel table, so once the entry is gone
/// the unregister silently fails — and a Stopped shim's stale registration
/// would swallow every inbound datagram for that peer (delivered to a receiver
/// that drops them) for as long as it stays in the map.
pub fn clear_recv_callback_by_chan(chan: u64) {
    let mut map = RECV.lock().unwrap_or_else(|p| p.into_inner());
    let before = map.len();
    map.retain(|peer, c| {
        let owned = c.chan == chan;
        if owned {
            diag(format_args!(
                "clear_by_chan peer={:02x}{:02x}{:02x}{:02x} chan={chan} hits={}",
                peer[0], peer[1], peer[2], peer[3], c.hits
            ));
        }
        !owned
    });
    if map.len() == before {
        diag(format_args!("clear_by_chan chan={chan} no-entry"));
    }
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
    // `hits` counts within the CURRENT registration (reset by set), so the
    // trace shows whether each nominally-live window actually delivered into
    // the engine — the process-lifetime counters could not (a healthy first
    // window exhausted the "first 5" quota for the whole call).
    let target = {
        let mut map = RECV.lock().unwrap_or_else(|p| p.into_inner());
        map.get_mut(&peer).map(|c| {
            c.hits += 1;
            (c.cb, c.ctx, c.chan, c.hits)
        })
    };
    #[cfg(debug_assertions)]
    match target {
        Some((_, _, chan, hits)) => {
            if hits <= 3 || hits % 1000 == 0 {
                diag(format_args!(
                    "dispatch hit #{hits} peer={:02x}{:02x}{:02x}{:02x} chan={chan} len={}",
                    peer[0],
                    peer[1],
                    peer[2],
                    peer[3],
                    payload.len()
                ));
            }
        }
        None => {
            use std::sync::atomic::{AtomicU64, Ordering};
            static MISSES: AtomicU64 = AtomicU64::new(0);
            let n = MISSES.fetch_add(1, Ordering::Relaxed);
            if n < 5 || n.is_multiple_of(500) {
                // Snapshot who IS registered: an entry under a different peer
                // key at MISS time is a key-mismatch smoking gun; an empty
                // registry is the plain rebuild gap.
                let registered = {
                    let map = RECV.lock().unwrap_or_else(|p| p.into_inner());
                    map.iter()
                        .map(|(p, c)| {
                            format!(
                                "{:02x}{:02x}{:02x}{:02x}@chan{}",
                                p[0], p[1], p[2], p[3], c.chan
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(",")
                };
                diag(format_args!(
                    "dispatch MISS #{n} peer={:02x}{:02x}{:02x}{:02x} len={} registered=[{registered}]",
                    peer[0],
                    peer[1],
                    peer[2],
                    peer[3],
                    payload.len()
                ));
            }
        }
    }
    if let Some((cb, ctx, _, _)) = target {
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

/// Route one inbound media payload by its leading byte: a
/// [`MEDIA_BATCH_MAGIC`]-prefixed cell fans out to its packets, anything
/// else is a single raw RTP/RTCP datagram (raw RTP/RTCP starts 0x80..0xBF,
/// so the 0x42 magic can never be confused with a real packet). This is the
/// RELAY/DIRECT ingress twin of the onion feed's magic peel — the relay
/// sender now amortizes its ~24× per-packet envelope+padding overhead by
/// batching small audio/RTCP datagrams into one envelope, and this is where
/// the batch unfolds on the receiving endpoint.
pub fn dispatch_inbound_auto(peer: [u8; 32], payload: &[u8]) {
    let plaintext;
    let payload = if payload.starts_with(&MEDIA_SEALED_MAGIC) {
        let Some(cipher) = ({
            let map = RECV.lock().unwrap_or_else(|p| p.into_inner());
            map.get(&peer).map(|entry| Arc::clone(&entry.cipher))
        }) else {
            return;
        };
        let Some(opened) = cipher.open(payload) else {
            return;
        };
        plaintext = opened;
        plaintext.as_slice()
    } else {
        payload
    };
    if payload.first() == Some(&MEDIA_BATCH_MAGIC) {
        dispatch_inbound_batch(peer, &payload[1..]);
    } else {
        dispatch_inbound(peer, payload);
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

        set_recv_callback(
            peer_a,
            1,
            record,
            std::ptr::null_mut(),
            Arc::new(MediaCipher::default()),
        );
        // Registered peer → delivered (magic already stripped by the caller).
        dispatch_inbound(peer_a, &[0u8; 100]);
        // Unregistered peer → dropped (no channel open for it).
        dispatch_inbound(peer_b, &[0u8; 100]);
        assert_eq!(RX_CALLS.load(Ordering::SeqCst), 1, "only peer_a delivers");
        assert_eq!(RX_BYTES.load(Ordering::SeqCst), 100, "full payload length");

        // After clear → dropped, no callback invoked.
        clear_recv_callback(peer_a, 1);
        dispatch_inbound(peer_a, &[0u8; 50]);
        assert_eq!(RX_CALLS.load(Ordering::SeqCst), 1, "cleared peer is silent");
    }

    #[test]
    fn stale_channel_close_cannot_wipe_live_registration() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let peer = [5u8; 32];
        RX_CALLS.store(0, Ordering::SeqCst);
        RX_BYTES.store(0, Ordering::SeqCst);

        // Old channel registers, then a NEWER channel to the same peer
        // replaces the registration (failed direct attempt → relay switch,
        // or a session rebuild).
        set_recv_callback(
            peer,
            1,
            record,
            std::ptr::null_mut(),
            Arc::new(MediaCipher::default()),
        );
        set_recv_callback(
            peer,
            2,
            record,
            std::ptr::null_mut(),
            Arc::new(MediaCipher::default()),
        );
        // The old channel's straggling teardown must be a no-op...
        clear_recv_callback(peer, 1);
        dispatch_inbound(peer, &[0u8; 60]);
        assert_eq!(RX_CALLS.load(Ordering::SeqCst), 1, "live channel survives");
        // ...while the owner's own close still clears it.
        clear_recv_callback(peer, 2);
        dispatch_inbound(peer, &[0u8; 60]);
        assert_eq!(RX_CALLS.load(Ordering::SeqCst), 1, "owner close clears");
    }

    #[test]
    fn clear_by_chan_sweeps_the_orphaned_registration() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let peer = [6u8; 32];
        RX_CALLS.store(0, Ordering::SeqCst);

        // The host closed the channel before the engine unregistered: the
        // peer key is no longer resolvable, so teardown must sweep by chan —
        // otherwise the stale registration swallows the peer's media forever.
        set_recv_callback(
            peer,
            9,
            record,
            std::ptr::null_mut(),
            Arc::new(MediaCipher::default()),
        );
        clear_recv_callback_by_chan(9);
        dispatch_inbound(peer, &[0u8; 40]);
        assert_eq!(RX_CALLS.load(Ordering::SeqCst), 0, "swept registration");

        // ...and it must NOT touch a registration owned by another channel.
        set_recv_callback(
            peer,
            10,
            record,
            std::ptr::null_mut(),
            Arc::new(MediaCipher::default()),
        );
        clear_recv_callback_by_chan(9);
        dispatch_inbound(peer, &[0u8; 40]);
        assert_eq!(RX_CALLS.load(Ordering::SeqCst), 1, "live chan survives");
        clear_recv_callback(peer, 10);
    }

    #[test]
    fn media_magic_is_not_a_stream_proto_ver() {
        // A media cell's first byte must never be mistaken for a stream frame,
        // so the inbound demux can split the two by that byte alone.
        assert_ne!(MEDIA_MAGIC, veil_onion_stream::wire::PROTO_VER);
        assert_ne!(MEDIA_BATCH_MAGIC, veil_onion_stream::wire::PROTO_VER);
        assert_ne!(MEDIA_BATCH_MAGIC, MEDIA_MAGIC);
        assert_eq!(
            MEDIA_SEALED_MAGIC,
            veil_proto::ipc::RELAY_MEDIA_SEALED_MAGIC,
            "FFI and daemon compact-media markers must stay identical"
        );
    }

    #[test]
    fn media_cipher_roundtrip_reorders_and_rejects_replay() {
        let key = [0x31u8; 32];
        let mut tx = MediaCipherTx::new(&key);
        let mut rx = MediaCipherRx::new(&key);
        let first = tx.seal(b"first").unwrap();
        let second = tx.seal(b"second").unwrap();

        assert_eq!(rx.open(&second).as_deref(), Some(b"second".as_slice()));
        assert_eq!(rx.open(&first).as_deref(), Some(b"first".as_slice()));
        assert!(rx.open(&first).is_none(), "replay must be rejected");
    }

    #[test]
    fn unauthenticated_epoch_cannot_evict_receive_state() {
        let key = [0x42u8; 32];
        let mut tx = MediaCipherTx::new(&key);
        let mut rx = MediaCipherRx::new(&key);
        let valid = tx.seal(b"authenticated").unwrap();
        let mut forged = valid.clone();
        forged[4..12].copy_from_slice(&0xfeed_beefu64.to_be_bytes());

        assert!(rx.open(&forged).is_none());
        assert!(
            rx.epochs.is_empty(),
            "failed AEAD must not allocate an epoch"
        );
        assert_eq!(
            rx.open(&valid).as_deref(),
            Some(b"authenticated".as_slice())
        );
        assert_eq!(rx.epochs.len(), 1);
    }

    #[test]
    fn sealed_auto_dispatch_opens_once_before_routing() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let peer = [8u8; 32];
        let tx_key = [0x51u8; 32];
        let rx_key = [0x52u8; 32];
        let cipher = Arc::new(MediaCipher::default());
        cipher.configure(tx_key, rx_key);
        set_recv_callback(peer, 11, record, std::ptr::null_mut(), cipher);
        RX_CALLS.store(0, Ordering::SeqCst);
        RX_BYTES.store(0, Ordering::SeqCst);

        let mut remote_tx = MediaCipherTx::new(&rx_key);
        let sealed = remote_tx.seal(&[0x80u8; 120]).unwrap();
        dispatch_inbound_auto(peer, &sealed);
        dispatch_inbound_auto(peer, &sealed);
        assert_eq!(RX_CALLS.load(Ordering::SeqCst), 1, "replay is dropped");
        assert_eq!(RX_BYTES.load(Ordering::SeqCst), 120);
        clear_recv_callback(peer, 11);
    }

    #[test]
    fn batch_roundtrip_delivers_each_packet() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let peer = [3u8; 32];
        RX_CALLS.store(0, Ordering::SeqCst);
        RX_BYTES.store(0, Ordering::SeqCst);
        set_recv_callback(
            peer,
            1,
            record,
            std::ptr::null_mut(),
            Arc::new(MediaCipher::default()),
        );
        let packets = vec![vec![1u8; 120], vec![2u8; 130], vec![3u8; 140]];
        let encoded = encode_batch(&packets, 1024).unwrap();
        dispatch_inbound_batch(peer, &encoded);
        clear_recv_callback(peer, 1);
        assert_eq!(RX_CALLS.load(Ordering::SeqCst), 3);
        assert_eq!(RX_BYTES.load(Ordering::SeqCst), 390);
    }

    #[test]
    fn malformed_batch_is_atomic_drop() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let peer = [4u8; 32];
        RX_CALLS.store(0, Ordering::SeqCst);
        set_recv_callback(
            peer,
            1,
            record,
            std::ptr::null_mut(),
            Arc::new(MediaCipher::default()),
        );
        let mut encoded = encode_batch(&[vec![1u8; 10], vec![2u8; 10]], 128).unwrap();
        encoded.pop();
        dispatch_inbound_batch(peer, &encoded);
        clear_recv_callback(peer, 1);
        assert_eq!(RX_CALLS.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn auto_dispatch_routes_batch_and_raw_by_leading_byte() {
        // The relay ingress can receive either a single raw RTP/RTCP datagram
        // or a MEDIA_BATCH_MAGIC cell on the SAME callback. Routing must key on
        // the leading byte alone: raw RTP/RTCP starts 0x80..=0xDF (version bits
        // set), so the 0x42 batch magic is unambiguous. This locks that a raw
        // packet is never mis-parsed as a batch and a batch is always unfolded.
        let _guard = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let peer = [7u8; 32];
        set_recv_callback(
            peer,
            1,
            record,
            std::ptr::null_mut(),
            Arc::new(MediaCipher::default()),
        );

        // A batch cell → each inner packet delivered.
        RX_CALLS.store(0, Ordering::SeqCst);
        RX_BYTES.store(0, Ordering::SeqCst);
        let body = encode_batch(&[vec![0x80u8; 100], vec![0x90u8; 110]], 1024).unwrap();
        let mut cell = vec![MEDIA_BATCH_MAGIC];
        cell.extend_from_slice(&body);
        dispatch_inbound_auto(peer, &cell);
        assert_eq!(RX_CALLS.load(Ordering::SeqCst), 2, "batch unfolds to 2");
        assert_eq!(RX_BYTES.load(Ordering::SeqCst), 210);

        // A raw RTP datagram (leading 0x80) → delivered whole, once, unchanged.
        RX_CALLS.store(0, Ordering::SeqCst);
        RX_BYTES.store(0, Ordering::SeqCst);
        let mut rtp = vec![0x80u8];
        rtp.extend_from_slice(&[0xabu8; 149]);
        dispatch_inbound_auto(peer, &rtp);
        assert_eq!(RX_CALLS.load(Ordering::SeqCst), 1, "raw RTP delivered once");
        assert_eq!(RX_BYTES.load(Ordering::SeqCst), 150, "raw RTP intact");

        clear_recv_callback(peer, 1);
    }
}
