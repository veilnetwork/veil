//! Call-media plane: the end-to-end seal, the wire cell format, and the
//! inbound recv-callback registry every media transport dispatches through.
//!
//! Media (RTP/RTCP for calls) reaches a peer over one of three transports —
//! the anonymous onion circuit (see [`crate::anon_stream`]), a direct P2P app
//! datagram, or the ordinary Delivery relay. All three are lossy by design:
//! a datagram is dropped rather than retransmitted on loss, which is exactly
//! what a real-time codec wants (PLC/FEC absorb the gap and a stale packet is
//! worthless anyway).
//!
//! # Every transport carries the SAME sealed cell
//!
//! Whatever the route, what travels is one [`SealedMediaCell`]: ChaCha20-
//! Poly1305 over a per-call directional key, with the epoch salt and sequence
//! bound in as AAD. Nothing else is accepted, on any transport. Not an
//! optimization — the transports do not offer end-to-end protection on their
//! own:
//!
//! * **onion** — a media cell rides *inside* the circuit envelope but is not
//!   sealed to the destination. The relay that splices the two circuits must
//!   read `[cookie][peer_tag][cell]` to route it, so without this seal it reads
//!   every RTP byte of the call. Worse, that cookie is
//!   `app_id(peer_node, …, "stream-cookie-v2")` — a pure function of a PUBLIC
//!   node id — so the ingress point is computable by anyone, and writing into
//!   it needs no forgery at all.
//! * **direct P2P** — the session encrypts hop-to-hop to whatever node
//!   terminates it. That is transport security, not end-to-end security, and
//!   the `src_node_id` the receive path demuxes on is a claim, not a proof
//!   (see [`crate::veil_media_start_direct_receiver`]).
//! * **relay** — relay nodes see addressing metadata; the presealed path
//!   deliberately skips the daemon's per-packet ML-KEM envelope, so the seal is
//!   the only thing left. And an ML-KEM envelope proves confidentiality, never
//!   origin: anyone may encrypt TO a peer's public key.
//!
//! This is why the seal used to be relay-only and is not anymore. It arrived as
//! a *compact relay* optimization — its job was to let the daemon skip the
//! per-packet KEM envelope — so it was scoped to the one path that had such an
//! envelope, and the other two were left to "the transport already protects
//! this". For onion that sentence was simply false, and for direct it was true
//! only hop-by-hop. There is no longer an unsealed media path to choose, so
//! there is nothing to downgrade to.
//!
//! # What this module owns
//!
//!   * [`MediaCipher`] — the per-call directional seal and its replay window,
//!   * the wire magic bytes and the batch cell format,
//!   * the inbound recv-callback registry every transport dispatches into.
//!
//! The outbound send paths live in
//! [`crate::anon_stream::CircuitCells::send_datagram`] (onion) and in the
//! per-channel drain tasks in `lib.rs` (direct / relay); the per-channel FFI
//! (open / send / set-callback / close) lives in `lib.rs`.

use std::collections::{HashMap, VecDeque};
use std::os::raw::c_void;
use std::sync::{Arc, Condvar, LazyLock, Mutex};

use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use rand_core::{OsRng, RngCore};
use zeroize::{Zeroize, Zeroizing};

/// First byte of every media cell on the onion transport. Distinct from
/// `veil_onion_stream::wire::PROTO_VER` (= 1), so a media cell is already an
/// invalid stream frame (`Frame::decode` → `None`) and the reliable demux would
/// reject it outright — media and stream coexist on one circuit with zero
/// collision, separated only by this byte.
pub const MEDIA_MAGIC: u8 = 0x4d; // 'M'

/// First byte of a *plaintext* media cell containing several RTP/RTCP
/// datagrams. It lives INSIDE the seal: a batch envelope is media content, not
/// routing, so no one on the path may see it, rewrite it, or fan it out.
/// Distinct from the 0x80..0xBF range that opens a real RTP/RTCP packet, so the
/// receiver can tell a batch from a lone datagram by this byte alone.
pub const MEDIA_BATCH_MAGIC: u8 = 0x42; // 'B'

/// Symmetrically sealed media cell. The same marker is validated by the
/// local IPC daemon before it permits the compact presealed delivery path.
pub const MEDIA_SEALED_MAGIC: [u8; 4] = *b"VME1";
const MEDIA_SEALED_HEADER_LEN: usize = 4 + 8 + 8; // magic + epoch salt + sequence
const MEDIA_SEALED_TAG_LEN: usize = 16;
/// Bytes a seal adds on top of the plaintext cell. Send paths subtract this
/// from their cell budget.
pub(crate) const MEDIA_SEAL_OVERHEAD: usize = MEDIA_SEALED_HEADER_LEN + MEDIA_SEALED_TAG_LEN;
const MEDIA_SEALED_MAX_EPOCHS: usize = 4;
const MEDIA_SEALED_KDF_CONTEXT: &str = "xveil/call-media/channel-epoch/v1";
/// How many peers' replay windows are retained across channel teardown. A
/// device holds one live call at a time and rebuilds its route a handful of
/// times; eight covers that with room to spare and bounds the residue.
const MEDIA_REPLAY_PEERS_MAX: usize = 8;

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

/// What has already been played from one peer, per epoch salt.
///
/// Deliberately holds NO key material — a salt is a public wire value and a
/// window is a bitmap — because it deliberately OUTLIVES the channel that
/// learned it (see [`REPLAY`]).
#[derive(Default)]
struct MediaReplayState {
    epochs: VecDeque<(u64, MediaReplayWindow)>,
}

impl MediaReplayState {
    fn accepts(&self, salt: u64, sequence: u64) -> bool {
        match self.epochs.iter().find(|(known, _)| *known == salt) {
            Some((_, window)) => window.accepts(sequence),
            // An epoch we have never seen: any sequence in it is new. The salt
            // is not trusted at this point — the AEAD has not run yet — which
            // is exactly why nothing is RECORDED until `commit`.
            None => sequence != 0,
        }
    }

    /// Record an OPENED cell. Called only after the AEAD verified it, so an
    /// attacker's random salt cannot evict a live epoch's window.
    fn commit(&mut self, salt: u64, sequence: u64) {
        if let Some(index) = self.epochs.iter().position(|(known, _)| *known == salt) {
            if index != 0
                && let Some(epoch) = self.epochs.remove(index)
            {
                self.epochs.push_front(epoch);
            }
            if let Some((_, window)) = self.epochs.front_mut() {
                window.commit(sequence);
            }
            return;
        }
        if self.epochs.len() >= MEDIA_SEALED_MAX_EPOCHS {
            self.epochs.pop_back();
        }
        let mut window = MediaReplayWindow::default();
        window.commit(sequence);
        self.epochs.push_front((salt, window));
    }
}

/// Replay state per PEER, retained across channel teardown.
///
/// A call rebuilds its media channel as a matter of course — a failed direct
/// attempt falls back to relay, a session rebuild re-opens, an onion route is
/// repaired — and the rebuilt channel derives the same keys from the same call.
/// Were the window owned by the channel, every rebuild would hand an attacker a
/// clean slate: capture a sealed cell now, replay it into the new channel
/// afterwards, and the AEAD would accept it as a fresh epoch. Tying the window
/// to the peer instead makes "this cell was already played" survive the
/// rebuild.
///
/// Keyed by peer node id — an identifier the process already handles
/// everywhere — rather than by anything derived from the call key, so retaining
/// it leaves behind nothing that was not already public. Bounded LRU: a stale
/// entry can only ever cause a false reject if a future epoch salt collides
/// with a retained one (2^-64), and a new call's cells fail that peer's old
/// AEAD anyway.
type SharedReplayState = Arc<Mutex<MediaReplayState>>;
type ReplayLru = VecDeque<([u8; 32], SharedReplayState)>;

static REPLAY: LazyLock<Mutex<ReplayLru>> = LazyLock::new(|| Mutex::new(VecDeque::new()));

fn replay_state_for(peer: &[u8; 32]) -> SharedReplayState {
    let mut states = REPLAY.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(index) = states.iter().position(|(known, _)| known == peer)
        && let Some(entry) = states.remove(index)
    {
        let state = Arc::clone(&entry.1);
        states.push_front(entry);
        return state;
    }
    if states.len() >= MEDIA_REPLAY_PEERS_MAX {
        states.pop_back();
    }
    let state = Arc::new(Mutex::new(MediaReplayState::default()));
    states.push_front((*peer, Arc::clone(&state)));
    state
}

struct MediaCipherRx {
    master: Zeroizing<[u8; 32]>,
    /// Per-epoch derived keys, cached so a steady flow costs one AEAD and not
    /// a KDF as well. Purely a cache: it holds key material and therefore dies
    /// with the channel, while [`MediaCipherRx::replay`] does not.
    ciphers: VecDeque<(u64, ChaCha20Poly1305)>,
    replay: SharedReplayState,
}

fn open_sealed(cipher: &ChaCha20Poly1305, sequence: u64, sealed: &[u8]) -> Option<Vec<u8>> {
    cipher
        .decrypt(
            &media_nonce(sequence),
            Payload {
                msg: &sealed[MEDIA_SEALED_HEADER_LEN..],
                aad: &sealed[..MEDIA_SEALED_HEADER_LEN],
            },
        )
        .ok()
}

impl MediaCipherRx {
    fn new(peer: &[u8; 32], master: &[u8; 32]) -> Self {
        Self {
            master: Zeroizing::new(*master),
            ciphers: VecDeque::new(),
            replay: replay_state_for(peer),
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
        // Cheap rejection first: a cell we have already played never reaches
        // the AEAD, and a cell that fails the AEAD never reaches the window.
        if !self
            .replay
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .accepts(salt, sequence)
        {
            return None;
        }
        let plaintext = match self.ciphers.iter().position(|(known, _)| *known == salt) {
            Some(index) => {
                if index != 0
                    && let Some(entry) = self.ciphers.remove(index)
                {
                    self.ciphers.push_front(entry);
                }
                open_sealed(&self.ciphers.front()?.1, sequence, sealed)?
            }
            None => {
                // Derive for an unseen salt WITHOUT caching it: the salt is
                // still just a number an attacker wrote, and caching it before
                // the AEAD spoke would let random salts evict live epoch keys.
                let mut key = media_epoch_key(&self.master, salt);
                let cipher = ChaCha20Poly1305::new((&key).into());
                key.zeroize();
                let plaintext = open_sealed(&cipher, sequence, sealed)?;
                if self.ciphers.len() >= MEDIA_SEALED_MAX_EPOCHS {
                    self.ciphers.pop_back();
                }
                self.ciphers.push_front((salt, cipher));
                plaintext
            }
        };
        self.replay
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .commit(salt, sequence);
        Some(plaintext)
    }
}

/// Wire bytes produced by [`MediaCipher::seal`]. There is deliberately no other
/// constructor: a send path that wants to put media on the wire has to obtain
/// one of these, and the only way to obtain one is to seal.
pub(crate) struct SealedMediaCell(Vec<u8>);

impl SealedMediaCell {
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub(crate) fn into_vec(self) -> Vec<u8> {
        self.0
    }
}

/// Per-channel directional call-media cipher, required on EVERY transport. A
/// fresh random epoch salt is mixed into the TX sub-key, so rebuilding a route
/// during the same call can safely restart its sequence at one without nonce
/// reuse. RX keeps a tiny bounded set of recent epochs for make-before-break
/// overlap, shared per receive key (see [`RX_STATE`]).
pub(crate) struct MediaCipher {
    tx: Mutex<MediaCipherTx>,
    rx: Mutex<MediaCipherRx>,
}

impl MediaCipher {
    /// The peer and both directions are required arguments with no default:
    /// there is no half-configured or unconfigured `MediaCipher`, so no code
    /// path can end up asking "are we encrypted on this channel?" and getting
    /// `false`.
    ///
    /// `None` for key material that cannot separate the two directions. The
    /// check lives HERE, in the constructor, rather than beside the caller:
    /// equal TX/RX keys would make our own outbound cells open against our own
    /// inbound window — a reflector could loop a speaker's audio straight back
    /// at them — and an all-zero key is the shape a caller gets from a buffer it
    /// forgot to fill. A rule enforced next to one call site is a rule the next
    /// call site forgets.
    pub(crate) fn new(peer: &[u8; 32], tx_key: &[u8; 32], rx_key: &[u8; 32]) -> Option<Self> {
        if tx_key == rx_key
            || tx_key.iter().all(|byte| *byte == 0)
            || rx_key.iter().all(|byte| *byte == 0)
        {
            return None;
        }
        Some(Self {
            tx: Mutex::new(MediaCipherTx::new(tx_key)),
            rx: Mutex::new(MediaCipherRx::new(peer, rx_key)),
        })
    }

    pub(crate) fn seal(&self, plaintext: &[u8]) -> Option<SealedMediaCell> {
        self.tx
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .seal(plaintext)
            .map(SealedMediaCell)
    }

    fn open(&self, sealed: &[u8]) -> Option<Vec<u8>> {
        self.rx
            .lock()
            .unwrap_or_else(|p| p.into_inner())
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

/// Fold `packets` into ONE plaintext media cell: a lone datagram rides raw, a
/// group rides behind [`MEDIA_BATCH_MAGIC`]. `body_max` bounds the batch body
/// only — the caller sizes it so the sealed cell still fits its transport.
pub(crate) fn media_cell(mut packets: Vec<Vec<u8>>, body_max: usize) -> Option<Vec<u8>> {
    if packets.len() == 1 {
        return packets.pop().filter(|packet| !packet.is_empty());
    }
    let body = encode_batch(&packets, body_max)?;
    let mut cell = Vec::with_capacity(1 + body.len());
    cell.push(MEDIA_BATCH_MAGIC);
    cell.extend_from_slice(&body);
    Some(cell)
}

/// C recv callback: `(ctx, ptr, len)`. Invoked from the transport's feed task
/// once per inbound media datagram, after the seal has been opened. It must not
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
    /// The channel's end-to-end media cipher. Every inbound cell is opened with
    /// it before anything reaches the engine, on every transport.
    cipher: Arc<MediaCipher>,
}

/// Inbound recv callbacks keyed by PEER node id. Each transport's feed resolves
/// the sender node per cell, so dispatch is by-peer — one entry per open
/// channel.
static RECV: LazyLock<Mutex<HashMap<[u8; 32], RecvCb>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Dispatches currently INSIDE a host callback, counted per channel.
///
/// The registry lock is released before the FFI call — it has to be, or a
/// re-entrant set/clear from inside the callback deadlocks. That leaves a
/// window in which the callback pointer and its `ctx` have been taken out of
/// the map and not yet used, and unregistering did nothing about it: the host
/// cleared its callback, saw nothing pending on its own side (its counter only
/// starts once the callback is ENTERED), destroyed the object, and this side
/// then called into it (report9 V-01).
///
/// So clearing waits here. The count is taken under the SAME lock that hands
/// out the callback, which is what makes the wait exact: a dispatch that got a
/// target incremented before the entry could be removed, and one that finds no
/// entry never calls anything.
static IN_FLIGHT: LazyLock<(Mutex<HashMap<u64, u32>>, Condvar)> =
    LazyLock::new(|| (Mutex::new(HashMap::new()), Condvar::new()));

thread_local! {
    /// The channel this thread is currently dispatching, if any.
    ///
    /// A callback is allowed to clear its own registration, and waiting for
    /// itself to finish would hang forever. On this thread the callback is on
    /// the stack, so the host cannot be destroying the object from here.
    static DISPATCHING: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

/// How long a clear waits for an in-flight dispatch before giving up and
/// saying so.
///
/// Bounded rather than unbounded on purpose: a callback that never returns
/// would otherwise wedge teardown, which is a worse failure than the one this
/// closes and the exact shape of a bug this project has already been bitten by.
/// The host's own drain waits one second; this waits longer, because it is the
/// half that actually knows whether a call is in progress.
const QUIESCE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// Wait until no dispatch for `chan` is inside a host callback.
///
/// Call AFTER the entry is out of the map and with no registry lock held.
fn await_quiescent(chan: u64) {
    if DISPATCHING.with(std::cell::Cell::get) == Some(chan) {
        // Re-entrant clear from inside the callback itself.
        return;
    }
    let (lock, cv) = &*IN_FLIGHT;
    let mut counts = lock.lock().unwrap_or_else(|p| p.into_inner());
    let deadline = std::time::Instant::now() + QUIESCE_TIMEOUT;
    while counts.get(&chan).copied().unwrap_or(0) > 0 {
        let Some(left) = deadline.checked_duration_since(std::time::Instant::now()) else {
            diag(format_args!(
                "quiesce TIMEOUT chan={chan} in_flight={} — the host may free its \
                 context while a dispatch is still inside its callback",
                counts.get(&chan).copied().unwrap_or(0)
            ));
            return;
        };
        let (guard, _) = cv
            .wait_timeout(counts, left)
            .unwrap_or_else(|p| p.into_inner());
        counts = guard;
    }
}

/// Lightweight per-peer counter of media datagrams that OPENED against the
/// channel's key. A diagnostic stat that also lets a host poll receipt without
/// wiring a cross-thread recv callback — the Phase 2 two-node probe reads it via
/// `veil_media_recv_count`. It counts authenticated media only: a liveness
/// signal a stranger can advance is not a liveness signal.
static RECV_COUNT: LazyLock<Mutex<HashMap<[u8; 32], u64>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Register (or replace) the recv callback for media datagrams arriving from
/// `peer`.
pub(crate) fn set_recv_callback(
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
    // Replacing is an unregistration for whoever was there: its `ctx` is now
    // unreachable from the map, and the host is free to destroy it. Wait for
    // any dispatch still inside it, exactly as a clear does.
    //
    // Keyed on the CONTEXT, not just the channel (audit report10 #2). The
    // condition used to be `old.chan != chan` alone, so re-registering on the
    // same channel with a different ctx returned immediately -- and that is a
    // real sequence: a host swapping its receiver keeps the channel and hands
    // over a new context, then frees the old one on the strength of this call
    // having returned. A dispatch still inside the old callback then used
    // freed memory. The channel is not what the host destroys; the context is.
    if let Some(old) = replaced
        .as_ref()
        .filter(|old| old.chan != chan || old.ctx != ctx as usize)
    {
        await_quiescent(old.chan);
    }
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
pub(crate) fn clear_recv_callback(peer: [u8; 32], chan: u64) {
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
    // Registry lock dropped BEFORE waiting: a dispatch already inside a
    // callback holds no registry lock, but one about to start needs it.
    drop(map);
    if owned {
        await_quiescent(chan);
    }
}

/// Remove any registration owned by `chan`, regardless of peer key. Fallback
/// for the host clearing a callback AFTER it already closed the channel: the
/// normal clear resolves peer via the channel table, so once the entry is gone
/// the unregister silently fails — and a Stopped shim's stale registration
/// would swallow every inbound datagram for that peer (delivered to a receiver
/// that drops them) for as long as it stays in the map.
pub(crate) fn clear_recv_callback_by_chan(chan: u64) {
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
    let removed = map.len() != before;
    drop(map);
    if removed {
        await_quiescent(chan);
    } else {
        diag(format_args!("clear_by_chan chan={chan} no-entry"));
    }
}

/// Deliver one OPENED media datagram from `peer` to its registered callback.
/// Private on purpose: the only way in is through [`dispatch_inbound_auto`],
/// so no transport can acquire a shortcut past the seal. The registry lock is
/// released BEFORE the FFI call so a re-entrant set/clear from inside the
/// callback cannot deadlock.
///
/// That release is also what made unregistering unsafe, so the call is counted
/// in [`IN_FLIGHT`] while the registry is still held: clearing then waits for
/// it. Without that, "the callback is no longer registered" said nothing about
/// whether one was running (report9 V-01).
fn dispatch_inbound(peer: [u8; 32], payload: &[u8]) {
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
        let found = map.get_mut(&peer).map(|c| {
            c.hits += 1;
            (c.cb, c.ctx, c.chan, c.hits)
        });
        // Counted while the registry is still held, so a clear either removes
        // the entry before this (and there is no call to wait for) or waits for
        // this call to finish. There is no third order.
        if let Some((_, _, chan, _)) = found {
            let (lock, _) = &*IN_FLIGHT;
            *lock
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .entry(chan)
                .or_insert(0) += 1;
        }
        found
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
    if let Some((cb, ctx, chan, _)) = target {
        let previous = DISPATCHING.with(|c| c.replace(Some(chan)));
        cb(ctx as *mut c_void, payload.as_ptr(), payload.len());
        DISPATCHING.with(|c| c.set(previous));
        let (lock, cv) = &*IN_FLIGHT;
        let mut counts = lock.lock().unwrap_or_else(|p| p.into_inner());
        match counts.get_mut(&chan) {
            Some(n) if *n > 1 => *n -= 1,
            _ => {
                counts.remove(&chan);
            }
        }
        drop(counts);
        cv.notify_all();
    }
}

/// Fan out one OPENED batch cell. The entire cell is dropped on malformed
/// length/count data; partial delivery would make corruption depend on packet
/// position and complicate loss accounting.
fn dispatch_inbound_batch(peer: [u8; 32], body: &[u8]) {
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

/// THE inbound gate for call media, shared by every transport: open the cell
/// with the channel's own key, then route the plaintext by its leading byte
/// (a [`MEDIA_BATCH_MAGIC`] cell fans out to its packets, anything else is one
/// RTP/RTCP datagram).
///
/// Nothing reaches the media engine that did not open. Not "unless keys are
/// still being set up", not "unless this transport looks safe" — the decision
/// comes from OUR state (the cipher the channel was opened with) and never from
/// bytes the sender chose, and there is no branch for a channel without one
/// because such a channel cannot be opened.
///
/// This matters because the ingress is not a sender gate and never can be: a
/// media receive point is reachable anonymously by construction (the onion
/// cookie is a function of a public node id; a relayed Forward's
/// `sender_node_id` is an unauthenticated claim), and demanding a long-lived
/// sender identity here would break anonymity rather than fix injection. The
/// seal is what proves "whoever sent this holds this call's key".
pub(crate) fn dispatch_inbound_auto(peer: [u8; 32], payload: &[u8]) {
    // Resolve the channel's cipher BEFORE looking at the packet, so the
    // decision comes from our state and not from bytes the sender chose.
    let cipher = {
        let map = RECV.lock().unwrap_or_else(|p| p.into_inner());
        map.get(&peer).map(|entry| Arc::clone(&entry.cipher))
    };
    // No open channel for this peer: nothing to open the cell with, and the
    // engine has nowhere to put it either. Drop.
    let Some(cipher) = cipher else {
        return;
    };
    let Some(plaintext) = cipher.open(payload) else {
        return;
    };
    if plaintext.first() == Some(&MEDIA_BATCH_MAGIC) {
        dispatch_inbound_batch(peer, &plaintext[1..]);
    } else {
        dispatch_inbound(peer, &plaintext);
    }
}

/// Onion ingress: peel [`MEDIA_MAGIC`] off a circuit cell and hand the rest to
/// [`dispatch_inbound_auto`]. Returns whether the cell was a media cell (and
/// therefore must not continue into the reliable stream demux).
pub(crate) fn dispatch_onion_cell(peer: [u8; 32], cell: &[u8]) -> bool {
    if cell.first() != Some(&MEDIA_MAGIC) {
        return false;
    }
    dispatch_inbound_auto(peer, &cell[1..]);
    true
}

/// Number of inbound media datagrams from `peer` that opened against the
/// channel key since process start. The all-zero peer is a diagnostic wildcard:
/// it returns the GRAND TOTAL across every peer (useful when the sender's node
/// id isn't yet known to the receiver).
pub(crate) fn recv_count(peer: [u8; 32]) -> u64 {
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

    /// Replacing the callback on the SAME channel must wait for a dispatch
    /// still inside the old one (audit report10 #2).
    ///
    /// The condition used to be `old.chan != chan`, so a host that kept the
    /// channel and handed over a new context got an immediate return and then
    /// freed the old context out from under a running callback. Asserted on the
    /// observable consequence: the registering thread must not return until the
    /// in-flight callback has left.
    #[test]
    fn replacing_a_context_on_the_same_channel_waits_for_the_old_one() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        static INSIDE: AtomicUsize = AtomicUsize::new(0);
        static LEFT: AtomicUsize = AtomicUsize::new(0);
        INSIDE.store(0, Ordering::SeqCst);
        LEFT.store(0, Ordering::SeqCst);

        extern "C" fn slow(_ctx: *mut c_void, _ptr: *const u8, _len: usize) {
            INSIDE.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(std::time::Duration::from_millis(300));
            LEFT.fetch_add(1, Ordering::SeqCst);
        }

        let peer = [0x5au8; 32];
        let chan = 0xfeed_u64;
        let keys = cipher(peer, [1u8; 32], [2u8; 32]);
        set_recv_callback(peer, chan, slow, 0x1000 as *mut c_void, Arc::clone(&keys));

        // Stand in for a datagram arriving on a worker: mark the channel busy
        // the way dispatch does, so the registry sees an in-flight call.
        {
            let (lock, _) = &*IN_FLIGHT;
            *lock
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .entry(chan)
                .or_insert(0) += 1;
        }
        let busy = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(200));
            let (lock, cv) = &*IN_FLIGHT;
            let mut counts = lock.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(n) = counts.get_mut(&chan) {
                *n -= 1;
            }
            LEFT.fetch_add(1, Ordering::SeqCst);
            cv.notify_all();
        });

        // Same channel, DIFFERENT context. This is the call that used to
        // return straight away.
        let started = std::time::Instant::now();
        set_recv_callback(peer, chan, slow, 0x2000 as *mut c_void, keys);
        let waited = started.elapsed();
        busy.join().expect("busy thread panicked");

        assert!(
            waited >= std::time::Duration::from_millis(150),
            "registration returned after {waited:?} while a dispatch was still \
             inside the old callback — the host would free that context now",
        );
        assert!(
            LEFT.load(Ordering::SeqCst) >= 1,
            "the in-flight dispatch had not left when registration returned",
        );
        RECV.lock().unwrap_or_else(|p| p.into_inner()).remove(&peer);
    }

    /// Our side of a call with `peer`.
    fn cipher(peer: [u8; 32], tx_key: [u8; 32], rx_key: [u8; 32]) -> Arc<MediaCipher> {
        Arc::new(MediaCipher::new(&peer, &tx_key, &rx_key).expect("usable keys"))
    }

    /// The far end's mirror image, used only to SEAL what it sends us, so its
    /// own receive side is anchored to a throwaway id.
    fn peer_cipher(tx_key: [u8; 32], rx_key: [u8; 32]) -> MediaCipher {
        MediaCipher::new(&[0x99u8; 32], &tx_key, &rx_key).expect("usable keys")
    }

    /// Every transport veil actually implements for call media. A test that
    /// says "media" without saying which route is a test that leaves two of the
    /// three open.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Transport {
        /// `veil_media_open_channel` — cell rides the anonymous circuit behind
        /// [`MEDIA_MAGIC`]; ingress is `spawn_circuit_feed`.
        Onion,
        /// `veil_media_open_direct_channel` — cell rides one direct app
        /// datagram; ingress is `veil_media_dispatch_direct_datagram`.
        Direct,
        /// `veil_media_open_relay_channel` — cell rides a Delivery Forward;
        /// ingress is `veil_media_start_direct_receiver`'s drain.
        Relay,
    }

    const TRANSPORTS: [Transport; 3] = [Transport::Onion, Transport::Direct, Transport::Relay];

    impl Transport {
        /// The exact bytes this transport puts on the wire for one media cell.
        /// The onion path frames with [`MEDIA_MAGIC`]; direct and relay hand
        /// the sealed cell over as the whole datagram payload.
        fn wire(self, sealed: SealedMediaCell) -> Vec<u8> {
            match self {
                Transport::Onion => {
                    let mut cell = vec![MEDIA_MAGIC];
                    cell.extend_from_slice(sealed.as_bytes());
                    cell
                }
                Transport::Direct | Transport::Relay => sealed.into_vec(),
            }
        }

        /// The same framing applied to bytes that were never sealed — what an
        /// old unsealed sender, or an attacker imitating one, puts on the wire.
        fn wire_unsealed(self, plaintext: &[u8]) -> Vec<u8> {
            match self {
                Transport::Onion => {
                    let mut cell = vec![MEDIA_MAGIC];
                    cell.extend_from_slice(plaintext);
                    cell
                }
                Transport::Direct | Transport::Relay => plaintext.to_vec(),
            }
        }

        /// The receive-side entry point this transport's feed calls.
        fn ingress(self, peer: [u8; 32], wire: &[u8]) {
            match self {
                Transport::Onion => {
                    assert!(
                        dispatch_onion_cell(peer, wire),
                        "onion feed must recognise a media cell"
                    );
                }
                Transport::Direct | Transport::Relay => dispatch_inbound_auto(peer, wire),
            }
        }
    }

    /// A third party who never held the call key, writing straight into the
    /// receive point. It needs no forgery: the onion cookie is derived from a
    /// public node id, and a relayed Forward's sender id is an unauthenticated
    /// claim, so "arriving as the peer" is free.
    fn inject_as_peer(transport: Transport, peer: [u8; 32], plaintext: &[u8]) {
        // 1. plain RTP, exactly what an old unsealed sender would have sent —
        //    the shape the removed "no cipher configured" branch let through.
        transport.ingress(peer, &transport.wire_unsealed(plaintext));
        // 2. something that merely LOOKS sealed: right magic, wrong everything.
        let mut forged = MEDIA_SEALED_MAGIC.to_vec();
        forged.extend_from_slice(&7u64.to_be_bytes()); // salt
        forged.extend_from_slice(&1u64.to_be_bytes()); // sequence
        forged.extend_from_slice(plaintext);
        forged.extend_from_slice(&[0u8; MEDIA_SEALED_TAG_LEN]);
        transport.ingress(peer, &transport.wire_unsealed(&forged));
        // 3. sealed under a key of the attacker's own choosing.
        let attacker =
            MediaCipher::new(&[0x9au8; 32], &[0xa1u8; 32], &[0xa2u8; 32]).expect("usable");
        let sealed = attacker.seal(plaintext).expect("attacker can seal");
        transport.ingress(peer, &transport.wire(sealed));
    }

    #[test]
    fn honest_call_flows_on_every_transport() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        for (index, transport) in TRANSPORTS.into_iter().enumerate() {
            let peer = [0xc0 + index as u8; 32];
            let a_to_b = [0x11 + index as u8; 32];
            let b_to_a = [0x22 + index as u8; 32];
            // Us: TX a→b, RX b→a. The peer holds the mirror image.
            let ours = cipher(peer, a_to_b, b_to_a);
            let theirs = peer_cipher(b_to_a, a_to_b);
            set_recv_callback(peer, 1, record, std::ptr::null_mut(), Arc::clone(&ours));
            RX_CALLS.store(0, Ordering::SeqCst);
            RX_BYTES.store(0, Ordering::SeqCst);

            // One lone RTP packet.
            let rtp = vec![0x80u8; 160];
            let sealed = theirs.seal(&rtp).expect("peer seals");
            transport.ingress(peer, &transport.wire(sealed));
            assert_eq!(
                RX_CALLS.load(Ordering::SeqCst),
                1,
                "{transport:?}: honest RTP must reach the engine"
            );
            assert_eq!(
                RX_BYTES.load(Ordering::SeqCst),
                160,
                "{transport:?}: honest RTP must arrive intact"
            );

            // A batch of three, folded into one cell exactly as a drain does.
            let packets = vec![vec![0x80u8; 100], vec![0x90u8; 110], vec![0xa0u8; 120]];
            let cell = media_cell(packets, 1024).expect("batch folds");
            let sealed = theirs.seal(&cell).expect("peer seals the batch");
            transport.ingress(peer, &transport.wire(sealed));
            assert_eq!(
                RX_CALLS.load(Ordering::SeqCst),
                4,
                "{transport:?}: every batched packet must reach the engine"
            );
            assert_eq!(
                RX_BYTES.load(Ordering::SeqCst),
                160 + 330,
                "{transport:?}: batched packets must arrive intact"
            );

            // ...and the counter the host polls for liveness moved with them.
            assert_eq!(
                recv_count(peer),
                4,
                "{transport:?}: authenticated media is what liveness counts"
            );
            clear_recv_callback(peer, 1);
        }
    }

    #[test]
    fn injection_by_a_third_party_never_reaches_the_engine() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        for (index, transport) in TRANSPORTS.into_iter().enumerate() {
            let peer = [0xd0 + index as u8; 32];
            let a_to_b = [0x31 + index as u8; 32];
            let b_to_a = [0x41 + index as u8; 32];
            let ours = cipher(peer, a_to_b, b_to_a);
            let theirs = peer_cipher(b_to_a, a_to_b);
            set_recv_callback(peer, 2, record, std::ptr::null_mut(), Arc::clone(&ours));
            RX_CALLS.store(0, Ordering::SeqCst);

            // A third party naming itself as our call peer, on this transport.
            inject_as_peer(transport, peer, &[0x80u8; 160]);
            // ...and a batch, so the fan-out cannot become a second door.
            let batch = media_cell(vec![vec![0x80u8; 60], vec![0x90u8; 70]], 512).unwrap();
            inject_as_peer(transport, peer, &batch);
            assert_eq!(
                RX_CALLS.load(Ordering::SeqCst),
                0,
                "{transport:?}: a stranger's frame must not reach the engine"
            );
            assert_eq!(
                recv_count(peer),
                0,
                "{transport:?}: a stranger must not be able to fake liveness"
            );

            // Control: the honest peer, on the same channel, still gets in —
            // so the assertion above is not just "this transport is deaf".
            let sealed = theirs.seal(&[0x80u8; 160]).expect("peer seals");
            transport.ingress(peer, &transport.wire(sealed));
            assert_eq!(
                RX_CALLS.load(Ordering::SeqCst),
                1,
                "{transport:?}: the honest peer must still be heard"
            );
            clear_recv_callback(peer, 2);
        }
    }

    #[test]
    fn a_captured_cell_replayed_is_dropped_on_every_transport() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        for (index, transport) in TRANSPORTS.into_iter().enumerate() {
            let peer = [0xe0 + index as u8; 32];
            let a_to_b = [0x51 + index as u8; 32];
            let b_to_a = [0x61 + index as u8; 32];
            let ours = cipher(peer, a_to_b, b_to_a);
            let theirs = peer_cipher(b_to_a, a_to_b);
            set_recv_callback(peer, 3, record, std::ptr::null_mut(), Arc::clone(&ours));
            RX_CALLS.store(0, Ordering::SeqCst);

            // The attacker copies a genuine cell off the wire...
            let captured = transport.wire(theirs.seal(&[0x80u8; 200]).expect("peer seals"));
            transport.ingress(peer, &captured);
            assert_eq!(
                RX_CALLS.load(Ordering::SeqCst),
                1,
                "{transport:?}: the original must be delivered"
            );
            // ...and plays it back. Twice, in case the window only rejects the
            // immediate repeat.
            transport.ingress(peer, &captured);
            transport.ingress(peer, &captured);
            assert_eq!(
                RX_CALLS.load(Ordering::SeqCst),
                1,
                "{transport:?}: a replayed cell must be dropped"
            );

            // Out-of-order delivery is NOT a replay: a later cell that arrives
            // first must not lock the earlier one out.
            let first = transport.wire(theirs.seal(&[0x81u8; 50]).expect("peer seals"));
            let second = transport.wire(theirs.seal(&[0x82u8; 50]).expect("peer seals"));
            transport.ingress(peer, &second);
            transport.ingress(peer, &first);
            assert_eq!(
                RX_CALLS.load(Ordering::SeqCst),
                3,
                "{transport:?}: reordering must still deliver"
            );
            transport.ingress(peer, &first);
            assert_eq!(
                RX_CALLS.load(Ordering::SeqCst),
                3,
                "{transport:?}: the reordered cell replays no better"
            );
            clear_recv_callback(peer, 3);
        }
    }

    #[test]
    fn replay_survives_the_route_rebuild_that_a_call_performs_routinely() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let peer = [0xf1u8; 32];
        let a_to_b = [0x71u8; 32];
        let b_to_a = [0x72u8; 32];
        let theirs = peer_cipher(b_to_a, a_to_b);

        // Direct attempt: the peer's cell is delivered.
        let first = cipher(peer, a_to_b, b_to_a);
        set_recv_callback(peer, 10, record, std::ptr::null_mut(), first);
        RX_CALLS.store(0, Ordering::SeqCst);
        let captured = theirs.seal(&[0x80u8; 90]).expect("peer seals");
        let captured = Transport::Direct.wire(captured);
        Transport::Direct.ingress(peer, &captured);
        assert_eq!(RX_CALLS.load(Ordering::SeqCst), 1, "original delivered");

        // The call falls back to relay: a NEW channel, same call, therefore the
        // same derived keys. The window must not start over.
        clear_recv_callback(peer, 10);
        let second = cipher(peer, a_to_b, b_to_a);
        set_recv_callback(peer, 11, record, std::ptr::null_mut(), second);
        Transport::Relay.ingress(peer, &captured);
        assert_eq!(
            RX_CALLS.load(Ordering::SeqCst),
            1,
            "a cell captured before the rebuild must not replay after it"
        );

        // Control: the peer's NEXT cell still gets through the new channel.
        let fresh = Transport::Relay.wire(theirs.seal(&[0x80u8; 90]).expect("peer seals"));
        Transport::Relay.ingress(peer, &fresh);
        assert_eq!(
            RX_CALLS.load(Ordering::SeqCst),
            2,
            "the rebuilt channel must still carry the call"
        );
        clear_recv_callback(peer, 11);
    }

    #[test]
    fn a_cell_for_another_call_leg_does_not_open() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let peer = [0xf2u8; 32];
        let a_to_b = [0x81u8; 32];
        let b_to_a = [0x82u8; 32];
        let ours = cipher(peer, a_to_b, b_to_a);
        set_recv_callback(peer, 12, record, std::ptr::null_mut(), Arc::clone(&ours));
        RX_CALLS.store(0, Ordering::SeqCst);

        // Our OWN outbound cell, reflected back at us. With one shared key it
        // would open against our own receive window; with directional keys it
        // cannot, so a reflector cannot loop a speaker's audio back at them.
        let mine = ours.seal(&[0x80u8; 120]).expect("we seal");
        Transport::Direct.ingress(peer, mine.as_bytes());
        assert_eq!(
            RX_CALLS.load(Ordering::SeqCst),
            0,
            "our own outbound cell must not open on our inbound leg"
        );
        clear_recv_callback(peer, 12);
    }

    #[test]
    fn a_channel_cannot_be_opened_with_unusable_keys() {
        let peer = [0xf3u8; 32];
        assert!(MediaCipher::new(&peer, &[1u8; 32], &[2u8; 32]).is_some());
        assert!(
            MediaCipher::new(&peer, &[1u8; 32], &[1u8; 32]).is_none(),
            "one key for both directions collapses the reflection defence"
        );
        assert!(
            MediaCipher::new(&peer, &[0u8; 32], &[2u8; 32]).is_none(),
            "an unfilled tx buffer must not become a cipher"
        );
        assert!(
            MediaCipher::new(&peer, &[1u8; 32], &[0u8; 32]).is_none(),
            "an unfilled rx buffer must not become a cipher"
        );
    }

    #[test]
    fn dispatch_routes_by_peer_and_honors_clear() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let peer_a = [1u8; 32];
        let peer_b = [2u8; 32];
        RX_CALLS.store(0, Ordering::SeqCst);
        RX_BYTES.store(0, Ordering::SeqCst);

        let ours = cipher(peer_a, [0x11u8; 32], [0x12u8; 32]);
        let theirs = peer_cipher([0x12u8; 32], [0x11u8; 32]);
        set_recv_callback(peer_a, 1, record, std::ptr::null_mut(), ours);
        // Registered peer → delivered.
        let cell = Transport::Direct.wire(theirs.seal(&[0u8; 100]).unwrap());
        Transport::Direct.ingress(peer_a, &cell);
        // Unregistered peer → dropped (no channel open for it).
        let other = Transport::Direct.wire(theirs.seal(&[0u8; 100]).unwrap());
        Transport::Direct.ingress(peer_b, &other);
        assert_eq!(RX_CALLS.load(Ordering::SeqCst), 1, "only peer_a delivers");
        assert_eq!(RX_BYTES.load(Ordering::SeqCst), 100, "full payload length");

        // After clear → dropped, no callback invoked.
        clear_recv_callback(peer_a, 1);
        let late = Transport::Direct.wire(theirs.seal(&[0u8; 50]).unwrap());
        Transport::Direct.ingress(peer_a, &late);
        assert_eq!(RX_CALLS.load(Ordering::SeqCst), 1, "cleared peer is silent");
    }

    #[test]
    fn stale_channel_close_cannot_wipe_live_registration() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let peer = [5u8; 32];
        RX_CALLS.store(0, Ordering::SeqCst);
        RX_BYTES.store(0, Ordering::SeqCst);
        let theirs = peer_cipher([0x14u8; 32], [0x13u8; 32]);

        // Old channel registers, then a NEWER channel to the same peer
        // replaces the registration (failed direct attempt → relay switch,
        // or a session rebuild).
        set_recv_callback(
            peer,
            1,
            record,
            std::ptr::null_mut(),
            cipher(peer, [0x13u8; 32], [0x14u8; 32]),
        );
        set_recv_callback(
            peer,
            2,
            record,
            std::ptr::null_mut(),
            cipher(peer, [0x13u8; 32], [0x14u8; 32]),
        );
        // The old channel's straggling teardown must be a no-op...
        clear_recv_callback(peer, 1);
        let cell = Transport::Direct.wire(theirs.seal(&[0u8; 60]).unwrap());
        Transport::Direct.ingress(peer, &cell);
        assert_eq!(RX_CALLS.load(Ordering::SeqCst), 1, "live channel survives");
        // ...while the owner's own close still clears it.
        clear_recv_callback(peer, 2);
        let cell = Transport::Direct.wire(theirs.seal(&[0u8; 60]).unwrap());
        Transport::Direct.ingress(peer, &cell);
        assert_eq!(RX_CALLS.load(Ordering::SeqCst), 1, "owner close clears");
    }

    #[test]
    fn clear_by_chan_sweeps_the_orphaned_registration() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let peer = [6u8; 32];
        RX_CALLS.store(0, Ordering::SeqCst);
        let theirs = peer_cipher([0x16u8; 32], [0x15u8; 32]);

        // The host closed the channel before the engine unregistered: the
        // peer key is no longer resolvable, so teardown must sweep by chan —
        // otherwise the stale registration swallows the peer's media forever.
        set_recv_callback(
            peer,
            9,
            record,
            std::ptr::null_mut(),
            cipher(peer, [0x15u8; 32], [0x16u8; 32]),
        );
        clear_recv_callback_by_chan(9);
        let cell = Transport::Direct.wire(theirs.seal(&[0u8; 40]).unwrap());
        Transport::Direct.ingress(peer, &cell);
        assert_eq!(RX_CALLS.load(Ordering::SeqCst), 0, "swept registration");

        // ...and it must NOT touch a registration owned by another channel.
        set_recv_callback(
            peer,
            10,
            record,
            std::ptr::null_mut(),
            cipher(peer, [0x15u8; 32], [0x16u8; 32]),
        );
        clear_recv_callback_by_chan(9);
        let cell = Transport::Direct.wire(theirs.seal(&[0u8; 40]).unwrap());
        Transport::Direct.ingress(peer, &cell);
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
        assert_eq!(
            MEDIA_SEAL_OVERHEAD,
            MEDIA_SEALED_HEADER_LEN + MEDIA_SEALED_TAG_LEN,
            "send budgets subtract exactly what a seal adds"
        );
    }

    #[test]
    fn media_cipher_roundtrip_reorders_and_rejects_replay() {
        let key = [0x31u8; 32];
        let mut tx = MediaCipherTx::new(&key);
        let mut rx = MediaCipherRx::new(&[0x01u8; 32], &key);
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
        // A peer of its own: replay state is shared per peer, and this test
        // asserts on an untouched window.
        let mut rx = MediaCipherRx::new(&[0x02u8; 32], &key);
        let valid = tx.seal(b"authenticated").unwrap();
        let mut forged = valid.clone();
        forged[4..12].copy_from_slice(&0xfeed_beefu64.to_be_bytes());

        assert!(rx.open(&forged).is_none());
        assert!(
            rx.ciphers.is_empty(),
            "failed AEAD must not allocate an epoch key"
        );
        assert!(
            rx.replay
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .epochs
                .is_empty(),
            "failed AEAD must not touch the replay window either"
        );
        assert_eq!(
            rx.open(&valid).as_deref(),
            Some(b"authenticated".as_slice())
        );
        assert_eq!(rx.ciphers.len(), 1);
        assert_eq!(
            rx.replay
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .epochs
                .len(),
            1
        );
    }

    #[test]
    fn batch_roundtrip_delivers_each_packet() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let peer = [3u8; 32];
        RX_CALLS.store(0, Ordering::SeqCst);
        RX_BYTES.store(0, Ordering::SeqCst);
        let theirs = peer_cipher([0x18u8; 32], [0x17u8; 32]);
        set_recv_callback(
            peer,
            1,
            record,
            std::ptr::null_mut(),
            cipher(peer, [0x17u8; 32], [0x18u8; 32]),
        );
        let packets = vec![vec![1u8; 120], vec![2u8; 130], vec![3u8; 140]];
        let cell = media_cell(packets, 1024).unwrap();
        Transport::Relay.ingress(peer, theirs.seal(&cell).unwrap().as_bytes());
        clear_recv_callback(peer, 1);
        assert_eq!(RX_CALLS.load(Ordering::SeqCst), 3);
        assert_eq!(RX_BYTES.load(Ordering::SeqCst), 390);
    }

    #[test]
    fn malformed_batch_is_atomic_drop() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let peer = [4u8; 32];
        RX_CALLS.store(0, Ordering::SeqCst);
        let theirs = peer_cipher([0x1au8; 32], [0x19u8; 32]);
        set_recv_callback(
            peer,
            1,
            record,
            std::ptr::null_mut(),
            cipher(peer, [0x19u8; 32], [0x1au8; 32]),
        );
        // A truncated batch, sealed by the genuine peer: authentication says
        // nothing about well-formedness, so the fan-out must still refuse it
        // whole rather than deliver the packets it managed to parse.
        let mut cell = media_cell(vec![vec![1u8; 10], vec![2u8; 10]], 128).unwrap();
        cell.pop();
        Transport::Relay.ingress(peer, theirs.seal(&cell).unwrap().as_bytes());
        clear_recv_callback(peer, 1);
        assert_eq!(RX_CALLS.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn media_cell_folds_one_packet_raw_and_many_behind_the_batch_magic() {
        // A lone datagram must not pay a batch header, and a group must never
        // be mistaken for a datagram: raw RTP/RTCP opens 0x80..=0xBF, so the
        // 0x42 magic is unambiguous.
        let lone = media_cell(vec![vec![0x80u8; 100]], 1024).unwrap();
        assert_eq!(lone[0], 0x80, "a lone packet rides raw");
        assert_eq!(lone.len(), 100);

        let many = media_cell(vec![vec![0x80u8; 100], vec![0x90u8; 110]], 1024).unwrap();
        assert_eq!(many[0], MEDIA_BATCH_MAGIC, "a group rides behind the magic");

        assert!(media_cell(Vec::new(), 1024).is_none(), "nothing to send");
        assert!(
            media_cell(vec![vec![0x80u8; 100], vec![0x90u8; 110]], 16).is_none(),
            "an oversized batch must be refused, not truncated"
        );
    }
}

#[cfg(test)]
mod v01_quiescence_tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    static ENTERED: AtomicBool = AtomicBool::new(false);
    static RELEASE: AtomicBool = AtomicBool::new(false);
    static LEFT_AT: AtomicU64 = AtomicU64::new(0);
    static CLEARED_AT: AtomicU64 = AtomicU64::new(0);
    static TICK: AtomicU64 = AtomicU64::new(0);

    /// Stands in for the host's callback: announces that it is INSIDE, waits to
    /// be let go, and stamps the moment it leaves.
    extern "C" fn slow_cb(_ctx: *mut c_void, _ptr: *const u8, _len: usize) {
        ENTERED.store(true, Ordering::SeqCst);
        while !RELEASE.load(Ordering::SeqCst) {
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        LEFT_AT.store(TICK.fetch_add(1, Ordering::SeqCst), Ordering::SeqCst);
    }

    fn cipher() -> Arc<MediaCipher> {
        Arc::new(
            MediaCipher::new(&[0x33u8; 32], &[0xa1u8; 32], &[0xa2u8; 32]).expect("usable keys"),
        )
    }

    /// Unregistering must not return while a dispatch is inside the callback.
    ///
    /// This is the whole of V-01. The host clears its callback, sees nothing
    /// pending on ITS counter — which only starts once the callback is entered
    /// — destroys the object, and this side calls into it. The window is
    /// between taking `(cb, ctx)` out of the map and using them, so the test
    /// parks a dispatch exactly there.
    #[test]
    fn clearing_waits_for_a_dispatch_already_inside_the_callback() {
        let peer = [0x11u8; 32];
        let chan = 4242u64;
        ENTERED.store(false, Ordering::SeqCst);
        RELEASE.store(false, Ordering::SeqCst);
        TICK.store(1, Ordering::SeqCst);

        set_recv_callback(peer, chan, slow_cb, std::ptr::null_mut(), cipher());

        let dispatcher = std::thread::spawn(move || {
            dispatch_inbound(peer, b"payload");
        });
        // Wait until the callback is genuinely inside; without this the clear
        // could win the race for a reason that has nothing to do with the fix.
        for _ in 0..500 {
            if ENTERED.load(Ordering::SeqCst) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        assert!(ENTERED.load(Ordering::SeqCst), "the callback never started");

        let clearer = std::thread::spawn(move || {
            clear_recv_callback(peer, chan);
            CLEARED_AT.store(TICK.fetch_add(1, Ordering::SeqCst), Ordering::SeqCst);
        });

        // Give the clear a real chance to return early if it is going to.
        std::thread::sleep(std::time::Duration::from_millis(60));
        RELEASE.store(true, Ordering::SeqCst);

        dispatcher.join().unwrap();
        clearer.join().unwrap();

        assert!(
            LEFT_AT.load(Ordering::SeqCst) < CLEARED_AT.load(Ordering::SeqCst),
            "clear returned at {} while the callback only left at {} — the host \
             is free to destroy its context under a call already in flight",
            CLEARED_AT.load(Ordering::SeqCst),
            LEFT_AT.load(Ordering::SeqCst)
        );
    }

    /// A clear with nothing in flight must not wait around.
    ///
    /// The other half: a barrier that always waits its full timeout would pass
    /// the test above and add two seconds to every channel teardown.
    #[test]
    fn clearing_an_idle_registration_returns_at_once() {
        let peer = [0x22u8; 32];
        let chan = 99u64;
        set_recv_callback(peer, chan, slow_cb, std::ptr::null_mut(), cipher());
        let started = std::time::Instant::now();
        clear_recv_callback(peer, chan);
        assert!(
            started.elapsed() < std::time::Duration::from_millis(500),
            "an idle clear waited {:?}",
            started.elapsed()
        );
    }
}
