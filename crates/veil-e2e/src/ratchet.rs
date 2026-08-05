//! The ratchet, spliced onto the paths messages actually travel.
//!
//! [`veil_ratchet`] is a primitive: it agrees a key, advances a chain, and
//! hands back opaque bytes. It holds no addresses, no certificates, and no
//! storage. This module is the seam between it and the two send paths this node
//! has — the relay-routed `DeliveryEnvelope` and the direct authenticated
//! session — plus their two receive paths.
//!
//! # What a conversation is keyed by
//!
//! A ratchet is a two-party object, and "party" here is a **device**, not an
//! account. Two of a contact's devices are two independent ratchets: they hold
//! different secrets, they count messages independently, and merging them would
//! feed one device's frames to the other's chain and destroy both. So the key
//! is the triple in [`ConversationKey`] — our device, their node, their device.
//! Our own node id is not in it: every conversation this store holds is ours,
//! and adding it would only make the key longer.
//!
//! # Where the state lives
//!
//! Not here, and not anywhere else in this tree. veil has one database and it
//! belongs to the mailbox; nothing on the send path or in the frame dispatcher
//! can reach it. Ratchet state is therefore held in memory by [`RatchetStore`]
//! and persisted by the host — in this project, xVeil's hidden volume.
//!
//! That makes durability a contract rather than an implementation detail, and
//! the failure mode is silent: a lost write is a lost message key, and the
//! message that needed it never opens and never reports why. So the store
//! counts. [`RatchetStore::version`] advances on every committed operation and
//! [`RatchetStore::drain_dirty`] names exactly the conversations whose bytes
//! changed. A host that persists what `drain_dirty` returns after every send
//! and every receive cannot lose a key; a host that polls on a timer can.
//!
//! # What opening one of these proves
//!
//! An [`E2E_MARKER`](veil_proto::E2E_MARKER) envelope is one ML-KEM
//! encapsulation to a published key — anyone who read that key can produce one,
//! so it proves nothing about who wrote it. A frame from here opens only under
//! a root both parties derived from key material only they hold. On the side
//! that *initiated*, that is conclusive from the first reply: the root mixes a
//! Diffie-Hellman against the responder's certified device key, so a frame that
//! opens came from the holder of that key. On the side that *accepted*, it is
//! conclusive only once the initiator's announced key has been matched against
//! the certificate that peer published — until then the message is genuine
//! ciphertext from someone, and [`Opened::authenticated`] says so.
//!
//! Nothing here signs anything. Deniability is a requirement of this project,
//! and the whole point of the construction is that every authenticator is a
//! symmetric tag either party could have produced.

use std::collections::BTreeMap;
use std::sync::Mutex;

use veil_proto::RATCHET_E2E_MARKER;
use veil_ratchet::{
    InitialMessage, OsRatchetRng, PQXDH_PROLOGUE_LEN, RatchetError, RatchetRng, RatchetSession,
    pqxdh,
};
use zeroize::Zeroizing;

use crate::MlKemSeedRing;

// ── Wire ─────────────────────────────────────────────────────────────────────

/// Payload version. There is no compatibility shim; nothing has shipped.
pub const RATCHET_PAYLOAD_V1: u8 = 1;

/// `kind` byte: a PQXDH prologue with a ratchet frame behind it.
const KIND_PROLOGUE: u8 = 0;
/// `kind` byte: a bare ratchet frame on an established session.
const KIND_FRAME: u8 = 1;

/// `marker(1) ‖ version(1) ‖ kind(1) ‖ sender_instance(16) ‖ recipient_instance(16)`
const HEADER_LEN: usize = 1 + 1 + 1 + 16 + 16;

/// Domain separator for the AEAD associated data. Bound into every tag,
/// transmitted in none of them.
const AD_LABEL: &[u8] = b"veil.ratchet.e2e.v1";

// ── Conversation key ─────────────────────────────────────────────────────────

/// Length of the host-facing storage key: `local_instance ‖ peer_node ‖ peer_instance`.
pub const CONVERSATION_KEY_LEN: usize = 16 + 32 + 16;

/// Which two devices a ratchet session belongs to.
///
/// Ordered fields, so the `BTreeMap` this keys iterates deterministically and a
/// host that lists conversations gets a stable order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConversationKey {
    /// Which of *our* devices holds this half of the conversation.
    pub local_instance_id: [u8; 16],
    /// The peer's node id.
    pub peer_node_id: [u8; 32],
    /// Which of the peer's devices is on the other end.
    pub peer_instance_id: [u8; 16],
}

impl ConversationKey {
    /// The bytes the host addresses this conversation's blob by.
    ///
    /// Flat and reversible on purpose: a host that has to re-key its store
    /// (a device is removed, a contact is forgotten) can decide what to drop by
    /// reading the key, without a side table mapping opaque digests back to
    /// peers. Nothing secret is in it — all three fields are public
    /// identifiers that already travel on the wire.
    #[must_use]
    pub fn storage_key(&self) -> [u8; CONVERSATION_KEY_LEN] {
        let mut out = [0u8; CONVERSATION_KEY_LEN];
        out[..16].copy_from_slice(&self.local_instance_id);
        out[16..48].copy_from_slice(&self.peer_node_id);
        out[48..].copy_from_slice(&self.peer_instance_id);
        out
    }

    /// Inverse of [`storage_key`](Self::storage_key).
    #[must_use]
    pub fn from_storage_key(bytes: &[u8; CONVERSATION_KEY_LEN]) -> Self {
        let mut local_instance_id = [0u8; 16];
        let mut peer_node_id = [0u8; 32];
        let mut peer_instance_id = [0u8; 16];
        local_instance_id.copy_from_slice(&bytes[..16]);
        peer_node_id.copy_from_slice(&bytes[16..48]);
        peer_instance_id.copy_from_slice(&bytes[48..]);
        Self {
            local_instance_id,
            peer_node_id,
            peer_instance_id,
        }
    }

    /// Lowercase hex of [`storage_key`](Self::storage_key), for a host whose
    /// store is keyed by strings.
    #[must_use]
    pub fn storage_key_hex(&self) -> String {
        veil_util::bytes_to_hex(&self.storage_key())
    }
}

// ── Errors ───────────────────────────────────────────────────────────────────

/// Why a ratchet payload could not be built or opened.
///
/// Coarse on the receive path by design: a peer must not learn which of "wrong
/// device", "no session", "forged tag" applies by watching what comes back, so
/// every caller here maps the whole enum to one outcome — the frame is dropped.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum RatchetSpliceError {
    /// The payload is not a ratchet payload, or is truncated.
    #[error("malformed ratchet payload: {0}")]
    Malformed(&'static str),

    /// A payload version this build does not implement.
    #[error("unsupported ratchet payload version {0}")]
    UnsupportedVersion(u8),

    /// Addressed to a different device of ours. Refused rather than attempted:
    /// the keys are per-device, so trying would only produce a decrypt failure
    /// that looks like a key mismatch.
    #[error("ratchet payload addressed to another instance")]
    NotForThisDevice,

    /// A bare frame arrived for a conversation we hold no session for. The
    /// prologue was lost, or the state was.
    #[error("no ratchet session for this conversation")]
    NoSession,

    /// The peer's certificate carries no usable device Diffie-Hellman key, so
    /// there is nothing to authenticate them by and no key agreement to run.
    #[error("peer certificate carries no ratchet key")]
    NoRatchetKey,

    /// This node has no sovereign device identity, so it has no instance a
    /// peer could address and no ratchet key it could have published. Running
    /// without one is a supported configuration, not a fault.
    #[error("no local device identity")]
    NoLocalInstance,

    /// The primitive refused. Includes
    /// [`PqDowngrade`](veil_ratchet::RatchetError::PqDowngrade) — a frame that
    /// dropped its post-quantum leg is refused here exactly as it is there,
    /// never accepted with a classical-only derivation.
    #[error(transparent)]
    Ratchet(#[from] RatchetError),
}

// ── The peer's half, as read from a verified certificate ─────────────────────

/// The recipient's published key material, taken from a certificate whose
/// signature chain the caller has already verified.
///
/// Borrowed rather than owned, and spelled out field by field rather than
/// taking `veil_types::VerifiedPeerCert`, so this crate keeps its dependency
/// list and every call site states where each value came from.
#[derive(Debug, Clone, Copy)]
pub struct PeerRatchetKeys<'a> {
    /// The peer's node id.
    pub node_id: &'a [u8; 32],
    /// The device whose certificate these keys came out of.
    pub instance_id: &'a [u8; 16],
    /// ML-KEM-768 encapsulation key (1184 bytes).
    pub mlkem_ek: &'a [u8],
    /// The device's rotating X25519 public key.
    pub ratchet_pk: &'a [u8; 32],
}

/// Our own half: who we are and what we can decrypt with.
///
/// The two identifiers are held by value, not borrowed: the instance id lives
/// behind a lock in [`RatchetRuntime`] because a device identity can be swapped
/// while the node runs, and 48 bytes is not worth a lifetime.
#[derive(Clone, Copy)]
pub struct RatchetIdentity<'a> {
    /// Our node id.
    pub local_node_id: [u8; 32],
    /// Which of our devices is speaking.
    pub local_instance_id: [u8; 16],
    /// The ring holding the current mailbox seed and its still-usable
    /// predecessors. Both halves of a certificate come out of it, in matched
    /// order, so a sender working from a week-old certificate still finds the
    /// pair it addressed.
    pub seed_ring: &'a MlKemSeedRing,
}

impl std::fmt::Debug for RatchetIdentity<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RatchetIdentity")
            .field(
                "local_node_id",
                &veil_util::bytes_to_hex(&self.local_node_id[..4]),
            )
            .finish_non_exhaustive()
    }
}

// ── Store ────────────────────────────────────────────────────────────────────

/// Magic for one conversation's persisted blob. Distinct from the primitive's
/// own `VSR1` because this wrapper carries fields the primitive does not know
/// about, and feeding one to the other's parser must fail on the tag.
pub const CONVERSATION_BLOB_MAGIC: [u8; 4] = *b"VRC1";
const CONVERSATION_BLOB_V1: u8 = 1;

struct Entry {
    session: RatchetSession,
    /// The peer's device X25519 key this session was keyed to.
    peer_ik: [u8; 32],
    /// `true` once that key is known to be the one the peer published.
    ///
    /// Always `true` on the side that initiated — it read the key out of a
    /// verified certificate before deriving anything. On the side that
    /// accepted it starts `false` and is raised the first time the peer's
    /// certificate is in hand, which may be several frames later.
    authenticated: bool,
    /// The PQXDH prologue to re-attach to outgoing frames until the peer
    /// answers. `None` once anything of theirs has opened.
    pending_prologue: Option<Vec<u8>>,
}

impl Entry {
    fn encode(&self) -> Zeroizing<Vec<u8>> {
        let session = self.session.export_state();
        let prologue = self.pending_prologue.as_deref().unwrap_or(&[]);
        let mut out = Vec::with_capacity(4 + 1 + 32 + 1 + 1 + 2 + prologue.len() + 4 + session.len());
        out.extend_from_slice(&CONVERSATION_BLOB_MAGIC);
        out.push(CONVERSATION_BLOB_V1);
        out.extend_from_slice(&self.peer_ik);
        out.push(u8::from(self.authenticated));
        match &self.pending_prologue {
            Some(p) => {
                out.push(1);
                out.extend_from_slice(&(p.len() as u16).to_be_bytes());
                out.extend_from_slice(p);
            }
            None => out.push(0),
        }
        out.extend_from_slice(&(session.len() as u32).to_be_bytes());
        out.extend_from_slice(&session);
        Zeroizing::new(out)
    }

    fn decode(bytes: &[u8]) -> Result<Self, RatchetSpliceError> {
        let mut at = 0usize;
        let mut take = |n: usize| -> Result<&[u8], RatchetSpliceError> {
            let end = at
                .checked_add(n)
                .ok_or(RatchetSpliceError::Malformed("length overflow"))?;
            if end > bytes.len() {
                return Err(RatchetSpliceError::Malformed("truncated conversation blob"));
            }
            let slice = &bytes[at..end];
            at = end;
            Ok(slice)
        };
        if take(4)? != CONVERSATION_BLOB_MAGIC {
            return Err(RatchetSpliceError::Malformed("bad conversation blob magic"));
        }
        let version = take(1)?[0];
        if version != CONVERSATION_BLOB_V1 {
            return Err(RatchetSpliceError::UnsupportedVersion(version));
        }
        let mut peer_ik = [0u8; 32];
        peer_ik.copy_from_slice(take(32)?);
        let authenticated = match take(1)?[0] {
            0 => false,
            1 => true,
            _ => return Err(RatchetSpliceError::Malformed("bad boolean")),
        };
        let pending_prologue = match take(1)?[0] {
            0 => None,
            1 => {
                let len = u16::from_be_bytes(
                    take(2)?
                        .try_into()
                        .map_err(|_| RatchetSpliceError::Malformed("prologue length"))?,
                ) as usize;
                Some(take(len)?.to_vec())
            }
            _ => return Err(RatchetSpliceError::Malformed("bad boolean")),
        };
        let session_len = u32::from_be_bytes(
            take(4)?
                .try_into()
                .map_err(|_| RatchetSpliceError::Malformed("session length"))?,
        ) as usize;
        let session = RatchetSession::import_state(take(session_len)?)?;
        if at != bytes.len() {
            return Err(RatchetSpliceError::Malformed(
                "trailing bytes in conversation blob",
            ));
        }
        Ok(Self {
            session,
            peer_ik,
            authenticated,
            pending_prologue,
        })
    }
}

struct Inner {
    entries: BTreeMap<ConversationKey, Entry>,
    version: u64,
    /// Conversations whose bytes changed, each against the version at which
    /// it was last marked. The version is what makes an acknowledgement safe:
    /// a host clearing a mark is saying "the bytes I read at generation G are
    /// down", and a conversation re-marked after G has moved since.
    dirty: BTreeMap<ConversationKey, u64>,
}

impl Inner {
    /// One committed change: the version moves, and the conversation is marked
    /// AT the version it moved to.
    fn commit_change(&mut self, key: ConversationKey) {
        self.version = self.version.wrapping_add(1);
        self.dirty.insert(key, self.version);
    }
}

/// Every ratchet conversation this node currently holds, in memory.
///
/// The store is the thing the host persists. It is deliberately *not* a cache:
/// evicting an entry does not cost a round trip, it costs every message the
/// peer sends afterwards, because the chain cannot be rebuilt from anything
/// public. Entries leave only when the host says so
/// ([`forget`](Self::forget)).
pub struct RatchetStore {
    inner: Mutex<Inner>,
}

impl Default for RatchetStore {
    fn default() -> Self {
        Self::new()
    }
}

impl RatchetStore {
    /// An empty store. The host hydrates it with [`import`](Self::import).
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                entries: BTreeMap::new(),
                version: 0,
                dirty: BTreeMap::new(),
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// How many committed operations this store has performed.
    ///
    /// Monotonic and never reset, including across [`import`](Self::import), so
    /// a host can tell "nothing happened" from "something happened and I read
    /// it twice". It counts *committed* work only: a forged frame moves
    /// nothing and does not advance this.
    #[must_use]
    pub fn version(&self) -> u64 {
        self.lock().version
    }

    /// The conversations whose bytes changed since the last drain, and clear
    /// the set.
    ///
    /// The host writes each of these out before it treats the corresponding
    /// send or receive as complete. Draining without persisting loses the
    /// notification, not the state — a later mutation of the same conversation
    /// will name it again — but any message that arrives in between opens
    /// against whatever the host last stored, so the gap is real.
    #[must_use]
    pub fn drain_dirty(&self) -> Vec<ConversationKey> {
        let mut g = self.lock();
        std::mem::take(&mut g.dirty).into_keys().collect()
    }

    /// Take at most `max` of the conversations waiting to be persisted,
    /// leaving the rest marked.
    ///
    /// The bounded form exists for callers that copy into a fixed buffer — a
    /// host that asked for the whole set, got more than it could hold, and
    /// dropped the remainder would have lost the only notice it will get for
    /// those conversations until they change again.
    #[must_use]
    pub fn take_dirty(&self, max: usize) -> Vec<ConversationKey> {
        let mut g = self.lock();
        let taken: Vec<_> = g.dirty.keys().take(max).copied().collect();
        for key in &taken {
            g.dirty.remove(key);
        }
        taken
    }

    /// The conversations waiting to be persisted, WITHOUT clearing anything,
    /// and the generation to acknowledge them at.
    ///
    /// The destructive read is the wrong shape for a durable host. Between
    /// taking a mark and getting the bytes onto a disk there is an export, a
    /// worker hop and a commit, and a failure at any of them loses the only
    /// notice that conversation gets until it changes again — which for the
    /// rest of the same batch may be never. Here the marks stand until the host
    /// says the bytes are down.
    ///
    /// The returned generation is this store's version at the moment of the
    /// read. Hand it back to [`ack_dirty`](Self::ack_dirty): a conversation
    /// that changed in between was re-marked at a LATER version and keeps its
    /// mark, because the write about to land does not contain that change.
    #[must_use]
    pub fn peek_dirty(&self, max: usize) -> (Vec<ConversationKey>, u64) {
        let g = self.lock();
        (g.dirty.keys().take(max).copied().collect(), g.version)
    }

    /// Clear the marks of `keys` whose bytes are now durable, as of
    /// `generation`. Returns how many marks were cleared.
    ///
    /// A key marked after `generation` is left alone: acknowledging it would
    /// throw away the notice for a change the host has not written. A key that
    /// is not marked at all is not an error — a shutdown save writes everything
    /// held and acknowledges nothing.
    pub fn ack_dirty(&self, keys: &[ConversationKey], generation: u64) -> usize {
        let mut g = self.lock();
        let mut cleared = 0;
        for key in keys {
            if g.dirty.get(key).is_some_and(|marked| *marked <= generation) {
                g.dirty.remove(key);
                cleared += 1;
            }
        }
        cleared
    }

    /// How many conversations are waiting to be persisted.
    #[must_use]
    pub fn dirty_len(&self) -> usize {
        self.lock().dirty.len()
    }

    /// Every conversation held, in key order.
    #[must_use]
    pub fn keys(&self) -> Vec<ConversationKey> {
        self.lock().entries.keys().copied().collect()
    }

    /// How many conversations are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lock().entries.len()
    }

    /// Whether any conversation is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.lock().entries.is_empty()
    }

    /// One conversation's whole state, ready to be written out.
    ///
    /// Every byte is key material. The host stores it encrypted; in this
    /// project that is the hidden volume, which is why this returns
    /// [`Zeroizing`] rather than a plain `Vec`.
    #[must_use]
    pub fn export(&self, key: &ConversationKey) -> Option<Zeroizing<Vec<u8>>> {
        self.lock().entries.get(key).map(Entry::encode)
    }

    /// Put a conversation back, from bytes [`export`](Self::export) produced.
    ///
    /// Replaces whatever is held under that key. Importing does not mark the
    /// conversation dirty — the host just read it, so writing it straight back
    /// would be pointless — but it does advance
    /// [`version`](Self::version), because the store's contents changed.
    pub fn import(&self, key: &ConversationKey, blob: &[u8]) -> Result<(), RatchetSpliceError> {
        let entry = Entry::decode(blob)?;
        let mut g = self.lock();
        g.entries.insert(*key, entry);
        g.version = g.version.wrapping_add(1);
        Ok(())
    }

    /// Drop a conversation. Returns whether one was held.
    ///
    /// Irreversible: nothing public can rebuild the chain, so every message the
    /// peer has already sealed to it is gone. The peer will open a fresh
    /// conversation on their next prologue.
    pub fn forget(&self, key: &ConversationKey) -> bool {
        let mut g = self.lock();
        let had = g.entries.remove(key).is_some();
        if had {
            g.commit_change(*key);
        }
        had
    }

    /// Whether a session exists for this conversation.
    #[must_use]
    pub fn has_session(&self, key: &ConversationKey) -> bool {
        self.lock().entries.contains_key(key)
    }
}

// ── Sealing ──────────────────────────────────────────────────────────────────

/// Bind who is speaking to whom into the tag, without transmitting it.
///
/// Directional: the sender's identifiers come first, so a frame cannot be
/// reflected back at its author and open. Neither side transmits this — both
/// reconstruct it, which is what makes `sender_node_id` in the outer envelope
/// binding rather than decorative: a relay that rewrites it produces a tag that
/// does not verify.
fn associated_data(
    sender_node_id: &[u8; 32],
    sender_instance_id: &[u8; 16],
    recipient_node_id: &[u8; 32],
    recipient_instance_id: &[u8; 16],
) -> Vec<u8> {
    let mut ad = Vec::with_capacity(AD_LABEL.len() + 32 + 16 + 32 + 16);
    ad.extend_from_slice(AD_LABEL);
    ad.extend_from_slice(sender_node_id);
    ad.extend_from_slice(sender_instance_id);
    ad.extend_from_slice(recipient_node_id);
    ad.extend_from_slice(recipient_instance_id);
    ad
}

fn encode_payload(
    kind: u8,
    sender_instance_id: &[u8; 16],
    recipient_instance_id: &[u8; 16],
    blob: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + blob.len());
    out.push(RATCHET_E2E_MARKER);
    out.push(RATCHET_PAYLOAD_V1);
    out.push(kind);
    out.extend_from_slice(sender_instance_id);
    out.extend_from_slice(recipient_instance_id);
    out.extend_from_slice(blob);
    out
}

/// Length of the delivery-ACK key carried in front of the application payload,
/// inside the ciphertext.
pub const ACK_KEY_LEN: usize = 32;

/// Seal one message for `peer`, opening the conversation if this is the first.
///
/// The whole first return value is the `DeliveryEnvelope.payload` (or the
/// direct session's app payload) — marker byte included, so a caller never
/// prepends anything and cannot forget to.
///
/// The second is the per-message delivery-ACK key, the counterpart of
/// [`encrypt_with_ack`](crate::encrypt_with_ack)'s. It is not derived from
/// anything: it is 32 random bytes carried *inside* the ciphertext, in front of
/// the application payload. That is strictly stronger than deriving it from a
/// key-encapsulation secret, because a party who later learns the recipient's
/// decapsulation seed still cannot reconstruct it — and it is what keeps a
/// relay from forging a DELIVERED and stopping a retransmit for a message it
/// never delivered.
///
/// First contact needs nothing online from the recipient: everything read here
/// is out of the certificate they already published and already signed.
pub fn seal(
    store: &RatchetStore,
    me: &RatchetIdentity<'_>,
    peer: PeerRatchetKeys<'_>,
    app_payload: &[u8],
) -> Result<(Vec<u8>, [u8; ACK_KEY_LEN]), RatchetSpliceError> {
    let mut ack_key = [0u8; ACK_KEY_LEN];
    OsRatchetRng.fill_bytes(&mut ack_key);
    let mut plaintext = Zeroizing::new(Vec::with_capacity(ACK_KEY_LEN + app_payload.len()));
    plaintext.extend_from_slice(&ack_key);
    plaintext.extend_from_slice(app_payload);
    seal_inner(store, me, peer, &plaintext).map(|payload| (payload, ack_key))
}

fn seal_inner(
    store: &RatchetStore,
    me: &RatchetIdentity<'_>,
    peer: PeerRatchetKeys<'_>,
    plaintext: &[u8],
) -> Result<Vec<u8>, RatchetSpliceError> {
    if peer.ratchet_pk == &[0u8; 32] {
        // The canonical low-order point: every Diffie-Hellman against it is a
        // constant the peer chose, so a certificate carrying one authenticates
        // nobody. The verifier already refuses these; refuse again here rather
        // than derive a root from a value someone else picked.
        return Err(RatchetSpliceError::NoRatchetKey);
    }
    let key = ConversationKey {
        local_instance_id: me.local_instance_id,
        peer_node_id: *peer.node_id,
        peer_instance_id: *peer.instance_id,
    };
    let ad = associated_data(
        &me.local_node_id,
        &me.local_instance_id,
        peer.node_id,
        peer.instance_id,
    );

    let mut g = store.lock();

    // Settle the conversation against the certificate BEFORE sealing anything
    // into it.
    //
    // `open` will accept a prologue addressed to our published keys from
    // whoever names a sender, because at first contact there is nothing to
    // check the announced device key against. It records that key and marks
    // the conversation unauthenticated. Here the caller has a certificate
    // whose signature chain it verified, so the claim can finally be judged —
    // and it has to be judged now, because using the entry means sealing our
    // plaintext to whoever announced that key. A stranger who got a prologue
    // in first would otherwise receive every message we send to this contact.
    if let Some((matches_certificate, proven)) = g
        .entries
        .get(&key)
        .map(|e| (e.peer_ik == *peer.ratchet_pk, e.authenticated))
        && !proven
    {
        if matches_certificate {
            // The announcement was true. Only the holder of that key's secret
            // could have agreed the root this conversation runs on, so the
            // peer is proven from here on and a later rotation of theirs must
            // not be read as a contradiction.
            if let Some(entry) = g.entries.get_mut(&key) {
                entry.authenticated = true;
            }
        } else {
            // It was not: an unverified claim against a verified certificate.
            // Drop it. That closes the disclosure and the denial of service
            // together — the stranger's session neither carries our plaintext
            // nor keeps the real contact's prologue out, because what replaces
            // it is a conversation we open ourselves, to the key the
            // certificate publishes.
            g.entries.remove(&key);
        }
    }

    let (kind, blob) = match g.entries.get_mut(&key) {
        Some(entry) => {
            let frame = entry.session.encrypt(plaintext, &ad)?;
            match &entry.pending_prologue {
                // Still no answer: re-attach the original prologue so a lost
                // first transmission does not strand the conversation. The
                // responder derives the same root from it and the ratchet's
                // skipped-key handling covers whichever frames were lost.
                Some(prologue) => {
                    let mut blob = prologue.clone();
                    blob.extend_from_slice(&frame);
                    (KIND_PROLOGUE, blob)
                }
                None => (KIND_FRAME, frame),
            }
        }
        None => {
            let mut rng = OsRatchetRng;
            let our_ik_sk = me.seed_ring.current_ratchet_sk();
            let mlkem_ek: &[u8; veil_ratchet::ML_KEM_768_EK_LEN] = peer
                .mlkem_ek
                .try_into()
                .map_err(|_| RatchetSpliceError::Ratchet(RatchetError::InvalidPqKey))?;
            let (message, session) = pqxdh::initiate(
                &our_ik_sk,
                pqxdh::Peers {
                    initiator_node_id: &me.local_node_id,
                    responder_node_id: peer.node_id,
                    responder_instance_id: peer.instance_id,
                },
                pqxdh::ResponderKeys {
                    ik: peer.ratchet_pk,
                    mlkem_ek,
                },
                plaintext,
                &ad,
                &mut rng,
            )?;
            let blob = message.encode();
            g.entries.insert(
                key,
                Entry {
                    session,
                    peer_ik: *peer.ratchet_pk,
                    // Read out of a certificate whose signature chain the
                    // caller verified, so the peer is proven from the reply on.
                    authenticated: true,
                    pending_prologue: Some(blob[..PQXDH_PROLOGUE_LEN].to_vec()),
                },
            );
            (KIND_PROLOGUE, blob)
        }
    };
    g.commit_change(key);
    drop(g);

    Ok(encode_payload(
        kind,
        &me.local_instance_id,
        peer.instance_id,
        &blob,
    ))
}

// ── Opening ──────────────────────────────────────────────────────────────────

/// One successfully opened ratchet payload.
#[derive(Debug)]
pub struct Opened {
    /// The application payload.
    pub plaintext: Vec<u8>,
    /// The per-message delivery-ACK key the sender put inside the ciphertext.
    /// Only the two endpoints hold it, so a relay cannot forge a DELIVERED.
    pub ack_key: [u8; ACK_KEY_LEN],
    /// The conversation it belongs to — what the host persists.
    pub key: ConversationKey,
    /// Whether the sender is cryptographically proven, not merely claimed.
    ///
    /// `false` only in one case: we accepted a conversation opened by someone
    /// whose certificate we did not have in hand, so the device key they
    /// announced has not been matched against anything they published. The
    /// message is still genuine ciphertext addressed to this device; it is the
    /// *name* on it that is unconfirmed. Callers surface this as
    /// `SenderProvenance::Claimed`, exactly as they do for the anonymous path.
    pub authenticated: bool,
}

/// Whether a payload is one of ours, cheaply, without parsing it.
#[must_use]
pub fn is_ratchet_payload(payload: &[u8]) -> bool {
    payload.first() == Some(&RATCHET_E2E_MARKER)
}

/// Open a ratchet payload from `sender_node_id`.
///
/// `published_peer_ik` is the device X25519 key that peer's verified
/// certificate currently carries, when the caller has it. It decides two
/// things, and both of them the same way — by whether the key a prologue
/// announces is the key the peer published:
///
/// * whether the sender is reported as proven;
/// * whether a prologue may take back a conversation some stranger opened
///   first. It may, because announcing the published key and still producing a
///   frame that opens takes that key's secret.
///
/// Passing `None` never prevents a message from being read — it only means the
/// result comes back unauthenticated and displaces nothing, and a later frame
/// on the same conversation will settle it once the certificate has been
/// resolved.
pub fn open(
    store: &RatchetStore,
    me: &RatchetIdentity<'_>,
    sender_node_id: &[u8; 32],
    payload: &[u8],
    published_peer_ik: Option<&[u8; 32]>,
    now_unix: u64,
) -> Result<Opened, RatchetSpliceError> {
    let mut opened = open_inner(store, me, sender_node_id, payload, published_peer_ik, now_unix)?;
    if opened.plaintext.len() < ACK_KEY_LEN {
        // Authenticated, so it came from the peer — but the peer built a
        // payload this version does not understand. Refuse rather than hand a
        // truncated application payload upward.
        return Err(RatchetSpliceError::Malformed("plaintext shorter than its ack key"));
    }
    let rest = opened.plaintext.split_off(ACK_KEY_LEN);
    opened
        .ack_key
        .copy_from_slice(&std::mem::replace(&mut opened.plaintext, rest));
    Ok(opened)
}

fn open_inner(
    store: &RatchetStore,
    me: &RatchetIdentity<'_>,
    sender_node_id: &[u8; 32],
    payload: &[u8],
    published_peer_ik: Option<&[u8; 32]>,
    now_unix: u64,
) -> Result<Opened, RatchetSpliceError> {
    if payload.len() <= HEADER_LEN {
        return Err(RatchetSpliceError::Malformed("shorter than a header"));
    }
    if payload[0] != RATCHET_E2E_MARKER {
        return Err(RatchetSpliceError::Malformed("not a ratchet payload"));
    }
    if payload[1] != RATCHET_PAYLOAD_V1 {
        return Err(RatchetSpliceError::UnsupportedVersion(payload[1]));
    }
    let kind = payload[2];
    let mut sender_instance_id = [0u8; 16];
    sender_instance_id.copy_from_slice(&payload[3..19]);
    let mut recipient_instance_id = [0u8; 16];
    recipient_instance_id.copy_from_slice(&payload[19..35]);
    if recipient_instance_id != me.local_instance_id {
        return Err(RatchetSpliceError::NotForThisDevice);
    }
    let blob = &payload[HEADER_LEN..];

    let key = ConversationKey {
        local_instance_id: me.local_instance_id,
        peer_node_id: *sender_node_id,
        peer_instance_id: sender_instance_id,
    };
    let ad = associated_data(
        sender_node_id,
        &sender_instance_id,
        &me.local_node_id,
        &me.local_instance_id,
    );
    let mut rng = OsRatchetRng;

    let (message, frame) = match kind {
        KIND_PROLOGUE => {
            let message = InitialMessage::decode(blob)?;
            let frame = message.first_frame().to_vec();
            (Some(message), frame)
        }
        KIND_FRAME => (None, blob.to_vec()),
        _ => return Err(RatchetSpliceError::Malformed("unknown payload kind")),
    };

    // Whether this prologue proves its own authorship.
    //
    // A prologue is sealed to our *published* keys, so producing one proves
    // nothing on its own — that is the whole reason an established
    // conversation is never re-keyed by one. But a prologue that announces the
    // device key the peer's verified certificate publishes AND opens is a
    // different object: the root is derived against that key, so only the
    // holder of its secret can have built a frame that decrypts. Nobody else
    // can reach this bar, whatever pair of device ids they name.
    let proves_authorship = message
        .as_ref()
        .is_some_and(|m| published_peer_ik == Some(m.initiator_ik()));

    // Whether an entry may be replaced by this prologue. Cheap, and read at
    // both ends of the key agreement below — the store is unlocked in between,
    // so what was true when the work started is re-asked before it lands.
    //
    // Two conversations may be displaced by a prologue that has proved its
    // authorship, and only those two:
    //
    // * one nothing has ever confirmed — a stranger who got in first holds it,
    //   and the contact whose certificate we verified is asking for it back;
    // * one we opened ourselves and have never heard a word back on — the peer
    //   is starting over, and there is nothing received to lose. Our own frames
    //   on it went unread either way.
    //
    // A proven, answered conversation is untouchable, so a stranger's prologue
    // and a replay of the peer's own both stop here — the second could
    // otherwise rewind a live chain.
    let displaceable =
        |e: &Entry| proves_authorship && (!e.authenticated || e.pending_prologue.is_some());

    // An established conversation is never re-keyed by an inbound prologue.
    // Anyone can produce one — a prologue is sealed to our *published* key —
    // so honouring a second one would let any stranger who names the right two
    // device ids replace a live session and take the conversation down with it.
    // The frame behind the prologue is tried against the session we already
    // hold, which is what a legitimate repeat (the peer has not seen our reply
    // yet) actually needs.
    //
    // Symmetric work only, on state that has to be under the lock anyway: a
    // decrypt walks one chain and at most one Diffie-Hellman step.
    {
        let mut g = store.lock();
        if let Some(entry) = g.entries.get_mut(&key) {
            match entry.session.decrypt(&frame, &ad, &mut rng) {
                Ok(plaintext) => {
                    // Something of theirs opened, so they have our half of the
                    // exchange and the prologue has done its job.
                    entry.pending_prologue = None;
                    if !entry.authenticated
                        && (published_peer_ik == Some(&entry.peer_ik) || proves_authorship)
                    {
                        entry.authenticated = true;
                    }
                    let authenticated = entry.authenticated;
                    g.commit_change(key);
                    return Ok(Opened {
                        plaintext,
                        ack_key: [0u8; ACK_KEY_LEN],
                        key,
                        authenticated,
                    });
                }
                Err(e) => {
                    if !displaceable(entry) {
                        return Err(RatchetSpliceError::Ratchet(e));
                    }
                }
            }
        } else if kind != KIND_PROLOGUE {
            // No session. Only a prologue can start one; a bare frame is
            // unreadable and saying so is not a leak — the sender learns
            // nothing they did not send.
            return Err(RatchetSpliceError::NoSession);
        }
    }
    let message = message.ok_or(RatchetSpliceError::NoSession)?;

    // Every device key a sender could still have addressed us at, paired with
    // the mailbox seed published beside it. The ring guarantees the two lists
    // correspond element for element, so a sender working from a week-old
    // certificate finds the pair it actually used.
    //
    // NOT under the store's lock. This is the expensive half — one ML-KEM
    // decapsulation and two Diffie-Hellmans per candidate, every candidate on
    // a miss — and the store is one lock for every conversation this node
    // holds. Running it while holding that lock let anyone who addressed a
    // prologue at this device stall every other send and receive for the
    // duration, for the price of one encapsulation and an instance id they
    // chose themselves. The state this reads is our own key ring, which the
    // store does not own; what the store has to say is asked again below,
    // after the work, before anything lands.
    let ratchet_secrets = me.seed_ring.ratchet_secrets(now_unix);
    let mlkem_seeds = me.seed_ring.decrypt_seeds(now_unix);
    let mut first_err: Option<RatchetSpliceError> = None;
    for (ik_sk, mlkem_seed) in ratchet_secrets.iter().zip(mlkem_seeds.iter()) {
        match pqxdh::accept(
            ik_sk,
            mlkem_seed,
            pqxdh::Peers {
                initiator_node_id: sender_node_id,
                responder_node_id: &me.local_node_id,
                responder_instance_id: &me.local_instance_id,
            },
            &message,
            &ad,
            &mut rng,
        ) {
            Ok((plaintext, session)) => {
                let peer_ik = *message.initiator_ik();
                let authenticated = published_peer_ik == Some(&peer_ik);
                let mut g = store.lock();
                // Ask the store again. Another thread may have opened this
                // conversation while the agreement above ran unlocked, and the
                // same rule decides now as decided then: a conversation that is
                // proven and answered is not overwritten. The message opened
                // regardless, so it is genuine and still goes up — it is only
                // the session that is dropped, in favour of the one already
                // held.
                if g.entries.get(&key).is_none_or(displaceable) {
                    g.entries.insert(
                        key,
                        Entry {
                            session,
                            peer_ik,
                            authenticated,
                            pending_prologue: None,
                        },
                    );
                    g.commit_change(key);
                }
                return Ok(Opened {
                    plaintext,
                    ack_key: [0u8; ACK_KEY_LEN],
                    key,
                    authenticated,
                });
            }
            // Keep the first refusal that says something. A wrong epoch fails
            // as `AuthFailed` and the next candidate is worth trying; a
            // downgrade attempt is a property of the frame and no candidate
            // will change it, so it must not be overwritten by the generic
            // failure of the last seed in the ring.
            Err(e) => {
                let e = RatchetSpliceError::Ratchet(e);
                if first_err.is_none() || matches!(e, RatchetSpliceError::Ratchet(RatchetError::PqDowngrade))
                {
                    first_err = Some(e);
                }
            }
        }
    }
    Err(first_err.unwrap_or(RatchetSpliceError::Ratchet(RatchetError::AuthFailed)))
}

// ── Peer ratchet-key directory ───────────────────────────────────────────────

/// `peer_node_id → device X25519 key from that peer's verified certificate`.
///
/// The exact counterpart of [`PeerMlKemCache`](crate::PeerMlKemCache), written
/// by whatever resolves and verifies certificates and read on the receive path,
/// which is synchronous and cannot walk a DHT. A miss costs authentication for
/// that one message, never readability.
pub type PeerRatchetKeyCache = std::collections::HashMap<[u8; 32], [u8; 32]>;

// ── The handle both paths hold ───────────────────────────────────────────────

/// Everything a send or a receive path needs to run the ratchet.
///
/// One type rather than five loose fields on two contexts, because the five
/// are only ever useful together: a node missing any of them cannot ratchet at
/// all, and the shape makes that a single `Option` instead of a combination
/// that has to be checked consistently in two crates.
///
/// Cheap to clone — every field is an `Arc` or an identifier.
#[derive(Clone)]
pub struct RatchetRuntime {
    /// The conversations, which the host persists.
    pub store: std::sync::Arc<RatchetStore>,
    /// Our mailbox keys, current and still-usable retired.
    pub seed_ring: std::sync::Arc<MlKemSeedRing>,
    /// Our node id.
    pub local_node_id: [u8; 32],
    /// Which of our devices we are, mirroring the active sovereign identity.
    ///
    /// Behind a lock and optional because both are true of the thing it
    /// mirrors: a node can run with no sovereign identity at all (and must —
    /// that is a standing decision), and an identity can be swapped while the
    /// node runs. Reading it per message is what keeps a swap from leaving one
    /// path addressing a device that is no longer us.
    pub local_instance_id: std::sync::Arc<std::sync::RwLock<Option<[u8; 16]>>>,
    /// Peers' device keys, from their verified certificates.
    pub peer_ratchet_keys: std::sync::Arc<std::sync::RwLock<PeerRatchetKeyCache>>,
}

impl std::fmt::Debug for RatchetRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RatchetRuntime")
            .field("conversations", &self.store.len())
            .field("has_instance", &self.identity().is_some())
            .finish_non_exhaustive()
    }
}

impl RatchetRuntime {
    /// Our half of a conversation, or `None` when this node has no device
    /// identity to speak as and therefore nothing a peer could address.
    #[must_use]
    pub fn identity(&self) -> Option<RatchetIdentity<'_>> {
        let instance = (*self
            .local_instance_id
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner))?;
        Some(RatchetIdentity {
            local_node_id: self.local_node_id,
            local_instance_id: instance,
            seed_ring: &self.seed_ring,
        })
    }

    /// The device key `peer` published, if a verified certificate for them has
    /// been resolved. `None` costs authentication for one message, never
    /// readability.
    #[must_use]
    pub fn published_ik(&self, peer_node_id: &[u8; 32]) -> Option<[u8; 32]> {
        self.peer_ratchet_keys
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(peer_node_id)
            .copied()
    }

    /// Seal for a peer whose certificate the caller has verified. See [`seal`].
    pub fn seal_for(
        &self,
        peer: PeerRatchetKeys<'_>,
        app_payload: &[u8],
    ) -> Result<(Vec<u8>, [u8; ACK_KEY_LEN]), RatchetSpliceError> {
        let me = self
            .identity()
            .ok_or(RatchetSpliceError::NoLocalInstance)?;
        seal(&self.store, &me, peer, app_payload)
    }

    /// Open a payload from `sender_node_id`. See [`open`].
    pub fn open_payload(
        &self,
        sender_node_id: &[u8; 32],
        payload: &[u8],
        now_unix: u64,
    ) -> Result<Opened, RatchetSpliceError> {
        let me = self
            .identity()
            .ok_or(RatchetSpliceError::NoLocalInstance)?;
        let published = self.published_ik(sender_node_id);
        open(
            &self.store,
            &me,
            sender_node_id,
            payload,
            published.as_ref(),
            now_unix,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DK_SEED_BYTES, EK_BYTES, MLKEM_SEED_MIN_OVERLAP_SECS};

    const NOW: u64 = 1_800_000_000;

    struct Device {
        node_id: [u8; 32],
        instance_id: [u8; 16],
        ring: MlKemSeedRing,
        store: RatchetStore,
    }

    fn device(tag: u8) -> Device {
        let seed = [tag; DK_SEED_BYTES];
        let (ek, _) = crate::keypair_from_dk_seed(&seed).expect("keypair");
        Device {
            node_id: [tag; 32],
            instance_id: [tag; 16],
            ring: MlKemSeedRing::new(0, seed, ek),
            store: RatchetStore::new(),
        }
    }

    impl Device {
        fn me(&self) -> RatchetIdentity<'_> {
            RatchetIdentity {
                local_node_id: self.node_id,
                local_instance_id: self.instance_id,
                seed_ring: &self.ring,
            }
        }
        fn ek(&self) -> [u8; EK_BYTES] {
            self.ring.current_ek()
        }
        fn ratchet_pk(&self) -> [u8; 32] {
            self.ring.current_ratchet_pk()
        }
    }

    fn keys<'a>(d: &'a Device, ek: &'a [u8; EK_BYTES], pk: &'a [u8; 32]) -> PeerRatchetKeys<'a> {
        PeerRatchetKeys {
            node_id: &d.node_id,
            instance_id: &d.instance_id,
            mlkem_ek: ek,
            ratchet_pk: pk,
        }
    }

    /// Alice seals to Bob; Bob opens it. Returns Bob's result.
    fn a_to_b(a: &Device, b: &Device, msg: &[u8]) -> Result<Opened, RatchetSpliceError> {
        let (ek, pk) = (b.ek(), b.ratchet_pk());
        let payload = seal(&a.store, &a.me(), keys(b, &ek, &pk), msg).expect("seal").0;
        let a_pk = a.ratchet_pk();
        open(
            &b.store,
            &b.me(),
            &a.node_id,
            &payload,
            Some(&a_pk),
            NOW,
        )
    }

    #[test]
    fn first_contact_opens_and_is_authenticated() {
        let (a, b) = (device(0xA1), device(0xB1));
        let opened = a_to_b(&a, &b, b"hello").expect("open");
        assert_eq!(opened.plaintext, b"hello");
        assert!(
            opened.authenticated,
            "the initiator announced the key Bob's certificate publishes"
        );
        assert_eq!(opened.key.peer_node_id, a.node_id);
        assert_eq!(opened.key.peer_instance_id, a.instance_id);
        assert_eq!(opened.key.local_instance_id, b.instance_id);
    }

    #[test]
    fn a_conversation_flows_both_ways() {
        let (a, b) = (device(0xA2), device(0xB2));
        a_to_b(&a, &b, b"one").expect("open");
        for i in 0..4u8 {
            let (ek, pk) = (a.ek(), a.ratchet_pk());
            let back = seal(&b.store, &b.me(), keys(&a, &ek, &pk), &[i; 9]).expect("seal").0;
            let b_pk = b.ratchet_pk();
            let got = open(&a.store, &a.me(), &b.node_id, &back, Some(&b_pk), NOW).expect("open");
            assert_eq!(got.plaintext, vec![i; 9]);
            assert!(got.authenticated);

            let fwd = a_to_b(&a, &b, &[i + 100; 3]).expect("open");
            assert_eq!(fwd.plaintext, vec![i + 100; 3]);
        }
    }

    #[test]
    fn the_first_payload_carries_a_prologue_and_later_ones_do_not() {
        let (a, b) = (device(0xA3), device(0xB3));
        let (ek, pk) = (b.ek(), b.ratchet_pk());
        let first = seal(&a.store, &a.me(), keys(&b, &ek, &pk), b"1").expect("seal").0;
        assert_eq!(first[2], KIND_PROLOGUE);

        // Still no answer from Bob, so the prologue is repeated — a lost first
        // transmission must not strand the conversation.
        let second = seal(&a.store, &a.me(), keys(&b, &ek, &pk), b"2").expect("seal").0;
        assert_eq!(second[2], KIND_PROLOGUE);
        assert_eq!(
            &second[HEADER_LEN..HEADER_LEN + PQXDH_PROLOGUE_LEN],
            &first[HEADER_LEN..HEADER_LEN + PQXDH_PROLOGUE_LEN],
            "a repeat must re-send the SAME prologue; a second key agreement \
             would derive an unrelated root and orphan the first"
        );

        // Bob answers. Now Alice knows he has it.
        let a_pk = a.ratchet_pk();
        open(&b.store, &b.me(), &a.node_id, &second, Some(&a_pk), NOW).expect("open");
        let (aek, apk) = (a.ek(), a.ratchet_pk());
        let reply = seal(&b.store, &b.me(), keys(&a, &aek, &apk), b"got it").expect("seal").0;
        let b_pk = b.ratchet_pk();
        open(&a.store, &a.me(), &b.node_id, &reply, Some(&b_pk), NOW).expect("open");

        let third = seal(&a.store, &a.me(), keys(&b, &ek, &pk), b"3").expect("seal").0;
        assert_eq!(third[2], KIND_FRAME, "the prologue must stop once answered");
    }

    #[test]
    fn a_lost_first_message_is_recovered_by_the_repeated_prologue() {
        let (a, b) = (device(0xA4), device(0xB4));
        let (ek, pk) = (b.ek(), b.ratchet_pk());
        let lost = seal(&a.store, &a.me(), keys(&b, &ek, &pk), b"lost").expect("seal").0;
        let kept = seal(&a.store, &a.me(), keys(&b, &ek, &pk), b"kept").expect("seal").0;
        drop(lost);
        let a_pk = a.ratchet_pk();
        let got = open(&b.store, &b.me(), &a.node_id, &kept, Some(&a_pk), NOW).expect("open");
        assert_eq!(got.plaintext, b"kept");
    }

    #[test]
    fn an_unknown_sender_key_opens_but_is_not_authenticated() {
        let (a, b) = (device(0xA5), device(0xB5));
        let (ek, pk) = (b.ek(), b.ratchet_pk());
        let payload = seal(&a.store, &a.me(), keys(&b, &ek, &pk), b"who am i").expect("seal").0;
        // Bob has not resolved Alice's certificate yet.
        let got = open(&b.store, &b.me(), &a.node_id, &payload, None, NOW).expect("open");
        assert_eq!(got.plaintext, b"who am i");
        assert!(
            !got.authenticated,
            "an unmatched device key is a claim, and must be reported as one"
        );

        // It settles the moment the certificate is in hand.
        let next = seal(&a.store, &a.me(), keys(&b, &ek, &pk), b"still me").expect("seal").0;
        let a_pk = a.ratchet_pk();
        let got = open(&b.store, &b.me(), &a.node_id, &next, Some(&a_pk), NOW).expect("open");
        assert!(got.authenticated);
    }

    #[test]
    fn a_sender_announcing_the_wrong_key_is_not_authenticated() {
        let (a, b) = (device(0xA6), device(0xB6));
        let (ek, pk) = (b.ek(), b.ratchet_pk());
        let payload = seal(&a.store, &a.me(), keys(&b, &ek, &pk), b"impostor").expect("seal").0;
        // Anyone can seal to Bob's published key and name any sender. Handing
        // Bob a DIFFERENT certificate for that name must not authenticate it.
        let someone_else = device(0xC6).ratchet_pk();
        let got = open(
            &b.store,
            &b.me(),
            &a.node_id,
            &payload,
            Some(&someone_else),
            NOW,
        )
        .expect("open");
        assert!(!got.authenticated);
    }

    #[test]
    fn a_stranger_cannot_reset_an_established_conversation() {
        // The denial-of-service a naive accept-always receive path allows:
        // anyone can build a prologue to Bob's published key naming Alice's
        // node and device. If that replaced the live session, one frame from a
        // stranger would take the real conversation down.
        let (a, b) = (device(0xA7), device(0xB7));
        a_to_b(&a, &b, b"real one").expect("open");

        let mut impostor = device(0xC7);
        impostor.node_id = a.node_id;
        impostor.instance_id = a.instance_id;
        let (ek, pk) = (b.ek(), b.ratchet_pk());
        let forged = seal(&impostor.store, &impostor.me(), keys(&b, &ek, &pk), b"reset")
            .expect("seal")
            .0;
        let a_pk = a.ratchet_pk();
        assert!(
            open(&b.store, &b.me(), &a.node_id, &forged, Some(&a_pk), NOW).is_err(),
            "a second prologue must not re-key a live conversation"
        );

        // And the real one still works.
        let got = a_to_b(&a, &b, b"still here").expect("open");
        assert_eq!(got.plaintext, b"still here");
    }

    /// A stranger's device, wearing the contact's two public identifiers.
    ///
    /// Everything this needs is public and resolvable: the victim's node and
    /// device ids, the keys they published, and the ids of the contact whose
    /// conversation is being taken.
    fn squatter_for(contact: &Device, tag: u8) -> Device {
        let mut s = device(tag);
        s.node_id = contact.node_id;
        s.instance_id = contact.instance_id;
        s
    }

    #[test]
    fn a_squatter_who_got_there_first_does_not_receive_what_we_send() {
        // The order the anti-reset rule does not cover: a stranger opens the
        // conversation BEFORE the real contact ever does. Nothing is re-keyed,
        // so the rule is satisfied — and the entry the stranger left behind is
        // then what every outgoing message to that contact is sealed with.
        // The stranger both plants it and, being the relay that claimed to be
        // the sender, sees the ciphertext.
        let (a, b) = (device(0x60), device(0x61));
        let squatter = squatter_for(&a, 0x62);

        let (bek, bpk) = (b.ek(), b.ratchet_pk());
        let grab = seal(
            &squatter.store,
            &squatter.me(),
            keys(&b, &bek, &bpk),
            b"i am alice",
        )
        .expect("seal")
        .0;
        let a_pk = a.ratchet_pk();
        let got = open(&b.store, &b.me(), &a.node_id, &grab, Some(&a_pk), NOW).expect("open");
        assert!(
            !got.authenticated,
            "the key it announced is not the one Alice published"
        );

        // Bob now writes to Alice, from the certificate he verified.
        let (aek, apk) = (a.ek(), a.ratchet_pk());
        let out = seal(
            &b.store,
            &b.me(),
            keys(&a, &aek, &apk),
            b"the account number is",
        )
        .expect("seal")
        .0;
        let b_pk = b.ratchet_pk();
        assert!(
            open(
                &squatter.store,
                &squatter.me(),
                &b.node_id,
                &out,
                Some(&b_pk),
                NOW
            )
            .is_err(),
            "the squatter read a message Bob wrote to Alice"
        );
        assert_eq!(
            open(&a.store, &a.me(), &b.node_id, &out, Some(&b_pk), NOW)
                .expect("Alice could not read a message addressed to her")
                .plaintext,
            b"the account number is"
        );
    }

    #[test]
    fn a_squatter_who_got_there_first_is_displaced_by_the_real_contact() {
        // The other half of the same order: the contact arrives second and
        // must be able to take the conversation back. She can, because her
        // prologue announces the key her certificate publishes and still
        // opens — which takes that key's secret and so cannot be imitated.
        let (a, b) = (device(0x63), device(0x64));
        let squatter = squatter_for(&a, 0x65);

        let (bek, bpk) = (b.ek(), b.ratchet_pk());
        let grab = seal(
            &squatter.store,
            &squatter.me(),
            keys(&b, &bek, &bpk),
            b"i am alice",
        )
        .expect("seal")
        .0;
        let a_pk = a.ratchet_pk();
        open(&b.store, &b.me(), &a.node_id, &grab, Some(&a_pk), NOW).expect("open");

        let real = a_to_b(&a, &b, b"it is actually me").expect("the real contact was locked out");
        assert_eq!(real.plaintext, b"it is actually me");
        assert!(real.authenticated);

        // And the squatter's session went with it.
        let more = seal(
            &squatter.store,
            &squatter.me(),
            keys(&b, &bek, &bpk),
            b"still here",
        )
        .expect("seal")
        .0;
        assert!(
            open(&b.store, &b.me(), &a.node_id, &more, Some(&a_pk), NOW).is_err(),
            "the squatter kept the conversation after being displaced"
        );

        // The conversation Alice took back keeps running.
        assert_eq!(
            a_to_b(&a, &b, b"and again").expect("open").plaintext,
            b"and again"
        );
    }

    #[test]
    fn concurrent_first_contact_settles_on_one_conversation() {
        // The key agreement runs with the store unlocked, so two prologues for
        // the same conversation can now be inside it at once. Whatever the
        // interleaving, exactly one session may be held and exactly one change
        // may be counted: a second insert would replace a session whose first
        // message has already been handed upward, and the peer's next frame
        // would arrive at a chain that never saw it.
        let (a, b) = (device(0x70), device(0x71));
        let (bek, bpk) = (b.ek(), b.ratchet_pk());
        let payload = seal(&a.store, &a.me(), keys(&b, &bek, &bpk), b"race")
            .expect("seal")
            .0;
        let a_pk = a.ratchet_pk();

        let results: Vec<_> = std::thread::scope(|s| {
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    s.spawn(|| open(&b.store, &b.me(), &a.node_id, &payload, Some(&a_pk), NOW))
                })
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().expect("worker panicked"))
                .collect()
        });

        let opened: Vec<_> = results.into_iter().flatten().collect();
        assert!(!opened.is_empty(), "nobody opened the prologue");
        for o in &opened {
            assert_eq!(o.plaintext, b"race");
            assert!(o.authenticated);
        }
        assert_eq!(b.store.len(), 1, "the same conversation was held twice");
        assert_eq!(
            b.store.version(),
            1,
            "a second agreement overwrote the session the first one reported"
        );
    }

    #[test]
    fn a_replay_of_the_peers_own_prologue_does_not_rewind_a_live_conversation() {
        // The cost of getting the displacement rule too wide, stated on its
        // own. A prologue that announces the published key and opens under it
        // is proof of authorship — but a relay that kept a copy of one can
        // present that same proof later. Re-deriving from it would rebuild the
        // conversation at its very first frame, hand the first message up a
        // second time, and throw away every key agreed since. A proven,
        // answered conversation is therefore untouchable no matter who asks.
        let (a, b) = (device(0x6E), device(0x6F));
        let (bek, bpk) = (b.ek(), b.ratchet_pk());
        let opening = seal(&a.store, &a.me(), keys(&b, &bek, &bpk), b"hello")
            .expect("seal")
            .0;
        let a_pk = a.ratchet_pk();
        open(&b.store, &b.me(), &a.node_id, &opening, Some(&a_pk), NOW).expect("open");

        let key = b.store.keys()[0];
        let before_blob = b.store.export(&key).expect("held");
        let before_version = b.store.version();

        assert!(
            open(&b.store, &b.me(), &a.node_id, &opening, Some(&a_pk), NOW).is_err(),
            "a replayed prologue was accepted a second time"
        );
        assert_eq!(b.store.version(), before_version);
        assert_eq!(
            *b.store.export(&key).expect("held"),
            *before_blob,
            "and it must not have moved a single byte"
        );
    }

    #[test]
    fn a_squatter_arriving_second_takes_nothing_from_an_unproven_conversation() {
        // The displacement rule's other edge, and the near miss it has to
        // survive. Bob accepted Alice's first contact before her certificate
        // resolved, so the conversation is genuine but unproven — exactly the
        // state a stranger would want to knock over. Being unproven is not
        // enough: the prologue must also announce the key Alice published, and
        // a stranger cannot produce one that announces her key AND opens.
        let (a, b) = (device(0x6B), device(0x6C));
        let (bek, bpk) = (b.ek(), b.ratchet_pk());
        let first = seal(&a.store, &a.me(), keys(&b, &bek, &bpk), b"hello")
            .expect("seal")
            .0;
        let got = open(&b.store, &b.me(), &a.node_id, &first, None, NOW).expect("open");
        assert!(!got.authenticated);

        let squatter = squatter_for(&a, 0x6D);
        let forged = seal(
            &squatter.store,
            &squatter.me(),
            keys(&b, &bek, &bpk),
            b"me instead",
        )
        .expect("seal")
        .0;
        let a_pk = a.ratchet_pk();
        assert!(
            open(&b.store, &b.me(), &a.node_id, &forged, Some(&a_pk), NOW).is_err(),
            "a stranger displaced a conversation it cannot prove is its own"
        );

        // Alice's conversation is untouched, and settles the moment she speaks
        // again against the certificate Bob now holds.
        let next = seal(&a.store, &a.me(), keys(&b, &bek, &bpk), b"still me")
            .expect("seal")
            .0;
        let got = open(&b.store, &b.me(), &a.node_id, &next, Some(&a_pk), NOW).expect("open");
        assert_eq!(got.plaintext, b"still me");
        assert!(got.authenticated);
    }

    #[test]
    fn a_contact_proven_before_a_rotation_keeps_the_conversation() {
        // The seal-side rule keys off the claim being unverified, NOT off the
        // keys differing. A contact rotates their device key on a schedule,
        // and once a conversation is proven the key it was agreed against is
        // history the ratchet moved past long ago — tearing it down and
        // starting over on every rotation would be a fresh way to lose mail.
        let (a, b) = (device(0x66), device(0x67));
        a_to_b(&a, &b, b"first").expect("open");

        let (new_ek, _) = crate::keypair_from_dk_seed(&[0x68; DK_SEED_BYTES]).expect("keypair");
        a.ring
            .rotate(
                NOW,
                1,
                [0x68; DK_SEED_BYTES],
                new_ek,
                MLKEM_SEED_MIN_OVERLAP_SECS,
            )
            .expect("rotate");

        let (aek, apk) = (a.ek(), a.ratchet_pk());
        let reply = seal(&b.store, &b.me(), keys(&a, &aek, &apk), b"still talking")
            .expect("seal")
            .0;
        assert_eq!(
            reply[2], KIND_FRAME,
            "a rotation must not replace the conversation"
        );
        let b_pk = b.ratchet_pk();
        assert_eq!(
            open(&a.store, &a.me(), &b.node_id, &reply, Some(&b_pk), NOW)
                .expect("open")
                .plaintext,
            b"still talking"
        );
    }

    #[test]
    fn a_peer_re_opening_a_conversation_we_never_heard_back_on_is_followed() {
        // Our prologue is outstanding and nothing has ever come back on it,
        // and the peer opens the conversation from their side — they lost
        // their state, or dropped one a stranger had taken. Their prologue is
        // provably theirs, there is nothing received to lose, and refusing it
        // would strand both ends for good: neither session can read the
        // other's frames and nothing on the wire would ever change that.
        let (a, b) = (device(0x69), device(0x6A));
        let (bek, bpk) = (b.ek(), b.ratchet_pk());
        seal(&a.store, &a.me(), keys(&b, &bek, &bpk), b"anyone there").expect("seal");

        let (aek, apk) = (a.ek(), a.ratchet_pk());
        let fresh = seal(&b.store, &b.me(), keys(&a, &aek, &apk), b"starting over")
            .expect("seal")
            .0;
        let b_pk = b.ratchet_pk();
        let got = open(&a.store, &a.me(), &b.node_id, &fresh, Some(&b_pk), NOW).expect("open");
        assert_eq!(got.plaintext, b"starting over");
        assert!(got.authenticated);

        // And the conversation now runs on the session the peer opened.
        let back = seal(&a.store, &a.me(), keys(&b, &bek, &bpk), b"here now")
            .expect("seal")
            .0;
        assert_eq!(back[2], KIND_FRAME);
        let a_pk = a.ratchet_pk();
        assert_eq!(
            open(&b.store, &b.me(), &a.node_id, &back, Some(&a_pk), NOW)
                .expect("open")
                .plaintext,
            b"here now"
        );
    }

    #[test]
    fn a_payload_for_another_device_is_refused_before_any_key_work() {
        let (a, b) = (device(0xA8), device(0xB8));
        let (ek, pk) = (b.ek(), b.ratchet_pk());
        let payload = seal(&a.store, &a.me(), keys(&b, &ek, &pk), b"x").expect("seal").0;
        let other = device(0xD8);
        let me = RatchetIdentity {
            local_node_id: b.node_id,
            local_instance_id: other.instance_id,
            seed_ring: &b.ring,
        };
        assert_eq!(
            open(&b.store, &me, &a.node_id, &payload, None, NOW).unwrap_err(),
            RatchetSpliceError::NotForThisDevice
        );
    }

    /// Cut the ML-KEM encapsulation key out of the ratchet frame behind a
    /// prologue and clear its presence flags — exactly the payload an attacker
    /// who wanted a classical-only ratchet would put on the wire.
    fn strip_the_post_quantum_leg(payload: &[u8]) -> Vec<u8> {
        const FRAME_FIXED_LEN: usize = 2 + 1 + 1 + 32 + 4 + 4;
        const EK_LEN: usize = 1184;
        let frame_at = HEADER_LEN + PQXDH_PROLOGUE_LEN;
        let mut out = payload[..frame_at + FRAME_FIXED_LEN].to_vec();
        out[frame_at + 3] = 0;
        out.extend_from_slice(&payload[frame_at + FRAME_FIXED_LEN + EK_LEN..]);
        out
    }

    #[test]
    fn stripping_the_post_quantum_leg_is_refused_at_first_contact() {
        // The property the whole hybrid exists for, stated where the payload is
        // parsed rather than only inside the primitive. First contact is where
        // it matters most: the epoch turns, so the encapsulation key is what
        // the new root would be derived from, and deriving without it is the
        // downgrade this protocol exists to rule out.
        let (a, b) = (device(0xA9), device(0xB9));
        let (ek, pk) = (b.ek(), b.ratchet_pk());
        let good = seal(&a.store, &a.me(), keys(&b, &ek, &pk), b"downgrade me").expect("seal").0;
        assert_eq!(good[2], KIND_PROLOGUE);

        let a_pk = a.ratchet_pk();
        assert_eq!(
            open(
                &b.store,
                &b.me(),
                &a.node_id,
                &strip_the_post_quantum_leg(&good),
                Some(&a_pk),
                NOW
            )
            .unwrap_err(),
            RatchetSpliceError::Ratchet(RatchetError::PqDowngrade),
            "a header with no ML-KEM leg must be refused outright"
        );
        assert!(
            b.store.is_empty(),
            "and must not have left a half-built session behind"
        );
        // The unmangled payload still opens, so the refusal was about the
        // missing leg and not about the surgery.
        assert_eq!(
            open(&b.store, &b.me(), &a.node_id, &good, Some(&a_pk), NOW)
                .expect("open")
                .plaintext,
            b"downgrade me"
        );
    }

    #[test]
    fn stripping_the_post_quantum_leg_mid_epoch_is_refused_too() {
        // Within an epoch nothing is derived from the encapsulation key, so
        // there is no root to protect — but the key sits inside the frame's
        // authenticated header, so cutting it out breaks the tag. Different
        // mechanism, same answer: refused, and the session does not move.
        let (a, b) = (device(0xB1), device(0xC1));
        a_to_b(&a, &b, b"establish").expect("open");
        let (ek, pk) = (b.ek(), b.ratchet_pk());
        let good = seal(&a.store, &a.me(), keys(&b, &ek, &pk), b"downgrade me").expect("seal").0;
        let key = b.store.keys()[0];
        let before = b.store.export(&key).expect("held");

        let a_pk = a.ratchet_pk();
        assert_eq!(
            open(
                &b.store,
                &b.me(),
                &a.node_id,
                &strip_the_post_quantum_leg(&good),
                Some(&a_pk),
                NOW
            )
            .unwrap_err(),
            RatchetSpliceError::Ratchet(RatchetError::AuthFailed),
        );
        assert_eq!(*b.store.export(&key).expect("held"), *before);
        assert_eq!(
            open(&b.store, &b.me(), &a.node_id, &good, Some(&a_pk), NOW)
                .expect("open")
                .plaintext,
            b"downgrade me"
        );
    }

    #[test]
    fn a_bare_frame_with_no_session_is_refused() {
        let (a, b) = (device(0xAA), device(0xBA));
        a_to_b(&a, &b, b"one").expect("open");
        let (ek, pk) = (b.ek(), b.ratchet_pk());
        // Establish so Alice stops repeating the prologue.
        let (aek, apk) = (a.ek(), a.ratchet_pk());
        let reply = seal(&b.store, &b.me(), keys(&a, &aek, &apk), b"hi").expect("seal").0;
        let b_pk = b.ratchet_pk();
        open(&a.store, &a.me(), &b.node_id, &reply, Some(&b_pk), NOW).expect("open");
        let bare = seal(&a.store, &a.me(), keys(&b, &ek, &pk), b"two").expect("seal").0;
        assert_eq!(bare[2], KIND_FRAME);

        // A peer that lost its state cannot read it.
        let fresh = device(0xBA);
        assert_eq!(
            open(&fresh.store, &b.me(), &a.node_id, &bare, None, NOW).unwrap_err(),
            RatchetSpliceError::NoSession
        );
    }

    #[test]
    fn a_forged_tag_moves_nothing() {
        let (a, b) = (device(0xAB), device(0xBB));
        a_to_b(&a, &b, b"one").expect("open");
        let (ek, pk) = (b.ek(), b.ratchet_pk());
        let good = seal(&a.store, &a.me(), keys(&b, &ek, &pk), b"two").expect("seal").0;

        let before_version = b.store.version();
        let before_blob = b
            .store
            .export(&ConversationKey {
                local_instance_id: b.instance_id,
                peer_node_id: a.node_id,
                peer_instance_id: a.instance_id,
            })
            .expect("held");

        let mut forged = good.clone();
        let last = forged.len() - 1;
        forged[last] ^= 0xFF;
        let a_pk = a.ratchet_pk();
        assert!(open(&b.store, &b.me(), &a.node_id, &forged, Some(&a_pk), NOW).is_err());

        assert_eq!(
            b.store.version(),
            before_version,
            "a forgery must not count as a committed operation"
        );
        let after_blob = b
            .store
            .export(&ConversationKey {
                local_instance_id: b.instance_id,
                peer_node_id: a.node_id,
                peer_instance_id: a.instance_id,
            })
            .expect("held");
        assert_eq!(*before_blob, *after_blob, "and must not move a single byte");

        // And the genuine frame still opens.
        assert_eq!(
            open(&b.store, &b.me(), &a.node_id, &good, Some(&a_pk), NOW)
                .expect("open")
                .plaintext,
            b"two"
        );
    }

    #[test]
    fn a_relay_rewriting_the_sender_breaks_the_tag() {
        // `sender_node_id` rides in the OUTER envelope, where any relay can
        // rewrite it. Binding it into the associated data is what makes it
        // load-bearing rather than decorative.
        let (a, b) = (device(0xAC), device(0xBC));
        let (ek, pk) = (b.ek(), b.ratchet_pk());
        let payload = seal(&a.store, &a.me(), keys(&b, &ek, &pk), b"x").expect("seal").0;
        let lied_about = [0x77u8; 32];
        assert!(open(&b.store, &b.me(), &lied_about, &payload, None, NOW).is_err());
    }

    #[test]
    fn state_survives_an_export_import_round_trip() {
        let (a, b) = (device(0xAD), device(0xBD));
        a_to_b(&a, &b, b"one").expect("open");
        let (ek, pk) = (b.ek(), b.ratchet_pk());
        a_to_b(&a, &b, b"two").expect("open");

        // Both ends go through the host's store and come back.
        for dev in [&a, &b] {
            for key in dev.store.keys() {
                let blob = dev.store.export(&key).expect("held");
                dev.store.forget(&key);
                assert!(!dev.store.has_session(&key));
                dev.store.import(&key, &blob).expect("import");
            }
        }

        // The conversation continues from exactly where it was.
        let third = seal(&a.store, &a.me(), keys(&b, &ek, &pk), b"three").expect("seal").0;
        let a_pk = a.ratchet_pk();
        let got = open(&b.store, &b.me(), &a.node_id, &third, Some(&a_pk), NOW).expect("open");
        assert_eq!(got.plaintext, b"three");
        assert!(got.authenticated, "the authenticated flag must survive too");

        let (aek, apk) = (a.ek(), a.ratchet_pk());
        let back = seal(&b.store, &b.me(), keys(&a, &aek, &apk), b"four").expect("seal").0;
        let b_pk = b.ratchet_pk();
        assert_eq!(
            open(&a.store, &a.me(), &b.node_id, &back, Some(&b_pk), NOW)
                .expect("open")
                .plaintext,
            b"four"
        );
    }

    #[test]
    fn a_half_persisted_conversation_still_repeats_its_prologue() {
        // The state that is easiest to lose and worst to lose: the initiator
        // has spoken, the responder has not answered, and the host restarts.
        // If the prologue does not survive the round trip the responder never
        // gets a root and every later frame is undecryptable.
        let (a, b) = (device(0xAE), device(0xBE));
        let (ek, pk) = (b.ek(), b.ratchet_pk());
        let lost = seal(&a.store, &a.me(), keys(&b, &ek, &pk), b"lost").expect("seal").0;
        drop(lost);

        let key = a.store.keys()[0];
        let blob = a.store.export(&key).expect("held");
        let restarted = RatchetStore::new();
        restarted.import(&key, &blob).expect("import");

        let again = seal(&restarted, &a.me(), keys(&b, &ek, &pk), b"again").expect("seal").0;
        assert_eq!(again[2], KIND_PROLOGUE);
        let a_pk = a.ratchet_pk();
        assert_eq!(
            open(&b.store, &b.me(), &a.node_id, &again, Some(&a_pk), NOW)
                .expect("open")
                .plaintext,
            b"again"
        );
    }

    #[test]
    fn every_committed_operation_names_the_conversation_to_persist() {
        let (a, b) = (device(0xAF), device(0xBF));
        assert_eq!(a.store.version(), 0);
        assert!(a.store.drain_dirty().is_empty());

        let (ek, pk) = (b.ek(), b.ratchet_pk());
        let payload = seal(&a.store, &a.me(), keys(&b, &ek, &pk), b"x").expect("seal").0;
        assert_eq!(a.store.version(), 1);
        let dirty = a.store.drain_dirty();
        assert_eq!(dirty.len(), 1);
        assert_eq!(dirty[0].peer_node_id, b.node_id);
        assert!(
            a.store.drain_dirty().is_empty(),
            "draining must clear, or a host cannot tell new work from old"
        );

        let a_pk = a.ratchet_pk();
        open(&b.store, &b.me(), &a.node_id, &payload, Some(&a_pk), NOW).expect("open");
        assert_eq!(b.store.version(), 1);
        assert_eq!(b.store.drain_dirty().len(), 1);
    }

    #[test]
    fn a_bounded_drain_leaves_what_it_could_not_take() {
        // A host copying into a fixed buffer must not lose the notice for the
        // conversations that did not fit — that notice is the only one it gets
        // until those conversations change again.
        let a = device(0xC8);
        let peers: Vec<_> = (0..5u8).map(|i| device(0xD0 + i)).collect();
        for b in &peers {
            let (ek, pk) = (b.ek(), b.ratchet_pk());
            seal(&a.store, &a.me(), keys(b, &ek, &pk), b"x").expect("seal");
        }
        assert_eq!(a.store.dirty_len(), 5);

        let first = a.store.take_dirty(2);
        assert_eq!(first.len(), 2);
        assert_eq!(a.store.dirty_len(), 3);
        let rest = a.store.take_dirty(99);
        assert_eq!(rest.len(), 3);
        assert_eq!(a.store.dirty_len(), 0);
        assert!(a.store.take_dirty(99).is_empty());

        // Every conversation was named exactly once across the two calls.
        let mut all: Vec<_> = first.into_iter().chain(rest).collect();
        all.sort();
        all.dedup();
        assert_eq!(all.len(), 5);
    }

    #[test]
    fn a_peek_consumes_nothing() {
        // The whole difference from a drain: reading the list must not be what
        // discharges the obligation, because between reading it and getting the
        // bytes onto a disk there is an export, a worker hop and a commit.
        let a = device(0xE0);
        let peers: Vec<_> = (0..3u8).map(|i| device(0xE1 + i)).collect();
        for b in &peers {
            let (ek, pk) = (b.ek(), b.ratchet_pk());
            seal(&a.store, &a.me(), keys(b, &ek, &pk), b"x").expect("seal");
        }

        let (first, gen_first) = a.store.peek_dirty(99);
        assert_eq!(first.len(), 3);
        assert_eq!(a.store.dirty_len(), 3, "peeking cleared a mark");
        let (again, gen_again) = a.store.peek_dirty(99);
        assert_eq!(again, first, "the same work, named the same way");
        assert_eq!(gen_again, gen_first);

        // Bounded the same way a drain is, and the remainder stays.
        let (bounded, _) = a.store.peek_dirty(2);
        assert_eq!(bounded.len(), 2);
        assert_eq!(a.store.dirty_len(), 3);
    }

    #[test]
    fn an_ack_clears_exactly_what_was_written() {
        let a = device(0xF0);
        let peers: Vec<_> = (0..3u8).map(|i| device(0xF1 + i)).collect();
        for b in &peers {
            let (ek, pk) = (b.ek(), b.ratchet_pk());
            seal(&a.store, &a.me(), keys(b, &ek, &pk), b"x").expect("seal");
        }

        let (batch, generation) = a.store.peek_dirty(2);
        assert_eq!(a.store.ack_dirty(&batch, generation), 2);
        assert_eq!(a.store.dirty_len(), 1);

        let (rest, gen_rest) = a.store.peek_dirty(99);
        assert_eq!(rest.len(), 1);
        assert_eq!(a.store.ack_dirty(&rest, gen_rest), 1);
        assert_eq!(a.store.dirty_len(), 0);
        // Acknowledging a conversation nobody marked is not an error: the
        // shutdown save writes everything held and marks nothing.
        assert_eq!(a.store.ack_dirty(&rest, gen_rest), 0);
    }

    #[test]
    fn a_conversation_that_moved_since_the_peek_keeps_its_mark() {
        // The reason the acknowledgement carries a generation at all. The host
        // read this conversation's bytes at G and is now writing them; the
        // conversation has moved since, and those bytes do not contain the
        // move. Clearing the mark here would throw away the only notice that
        // change gets — and the state that reaches the next launch would then
        // be the one from before it, which is a message key used twice.
        let (a, b) = (device(0x40), device(0x41));
        let (ek, pk) = (b.ek(), b.ratchet_pk());
        seal(&a.store, &a.me(), keys(&b, &ek, &pk), b"first").expect("seal");

        let (batch, generation) = a.store.peek_dirty(99);
        assert_eq!(batch.len(), 1);

        // The send that lands while the write for the previous one is in flight.
        seal(&a.store, &a.me(), keys(&b, &ek, &pk), b"second").expect("seal");

        assert_eq!(
            a.store.ack_dirty(&batch, generation),
            0,
            "a stale acknowledgement cleared a live mark"
        );
        assert_eq!(a.store.dirty_len(), 1);

        // And the next pass, whose generation covers the second send, does
        // clear it.
        let (again, gen_again) = a.store.peek_dirty(99);
        assert_eq!(a.store.ack_dirty(&again, gen_again), 1);
        assert_eq!(a.store.dirty_len(), 0);
    }

    #[test]
    fn a_write_that_never_landed_leaves_the_work_for_the_next_pass() {
        // A disk error, a closed worker, a crash between the export and the
        // commit: no acknowledgement, so the mark stands and the next flush
        // does the work again. Under a destructive read this conversation had
        // already been forgotten about — along with the rest of its batch.
        let (a, b) = (device(0x50), device(0x51));
        let (ek, pk) = (b.ek(), b.ratchet_pk());
        seal(&a.store, &a.me(), keys(&b, &ek, &pk), b"x").expect("seal");

        let (batch, _) = a.store.peek_dirty(99);
        assert_eq!(batch.len(), 1);
        // ... and the write fails here, so nothing is acknowledged.

        let (retried, generation) = a.store.peek_dirty(99);
        assert_eq!(retried, batch, "the work was lost with the notice");
        assert_eq!(a.store.ack_dirty(&retried, generation), 1);
        assert_eq!(a.store.dirty_len(), 0);
    }

    #[test]
    fn a_retired_device_key_still_opens_first_contact() {
        // A sender holding a week-old certificate derived the root from the
        // ratchet key in it. Rotating must not make their message vanish — the
        // same black hole the mailbox seed overlap exists to prevent.
        let (a, b) = (device(0xB0), device(0xC0));
        let (ek, pk) = (b.ek(), b.ratchet_pk());
        let payload = seal(&a.store, &a.me(), keys(&b, &ek, &pk), b"pre-rotation").expect("seal").0;

        let (new_ek, _) = crate::keypair_from_dk_seed(&[0xEE; DK_SEED_BYTES]).expect("keypair");
        b.ring
            .rotate(
                NOW,
                1,
                [0xEE; DK_SEED_BYTES],
                new_ek,
                MLKEM_SEED_MIN_OVERLAP_SECS,
            )
            .expect("rotate");
        assert_ne!(b.ring.current_ratchet_pk(), pk, "the key must have turned");

        let a_pk = a.ratchet_pk();
        assert_eq!(
            open(&b.store, &b.me(), &a.node_id, &payload, Some(&a_pk), NOW)
                .expect("a retired pair must still open")
                .plaintext,
            b"pre-rotation"
        );
    }

    #[test]
    fn a_certificate_with_no_ratchet_key_is_refused() {
        let (a, b) = (device(0xB2), device(0xC2));
        let ek = b.ek();
        let zero = [0u8; 32];
        assert_eq!(
            seal(&a.store, &a.me(), keys(&b, &ek, &zero), b"x").unwrap_err(),
            RatchetSpliceError::NoRatchetKey
        );
    }

    #[test]
    fn the_delivery_ack_key_reaches_the_recipient_and_nobody_else() {
        // Without this the DELIVERED acknowledgement for a ratcheted message
        // would be unauthenticated, and a relay could forge one to stop a
        // retransmit for a message it never delivered.
        let (a, b) = (device(0xB6), device(0xC6));
        let (ek, pk) = (b.ek(), b.ratchet_pk());
        let (payload, sent_key) =
            seal(&a.store, &a.me(), keys(&b, &ek, &pk), b"deliver me").expect("seal");
        assert_ne!(sent_key, [0u8; ACK_KEY_LEN]);
        assert!(
            !payload
                .windows(ACK_KEY_LEN)
                .any(|w| w == sent_key.as_slice()),
            "the ack key must be INSIDE the ciphertext, not beside it"
        );

        let a_pk = a.ratchet_pk();
        let got = open(&b.store, &b.me(), &a.node_id, &payload, Some(&a_pk), NOW).expect("open");
        assert_eq!(got.ack_key, sent_key);
        assert_eq!(got.plaintext, b"deliver me", "and must not leak into it");

        // Every message gets its own.
        let (_, second_key) = seal(&a.store, &a.me(), keys(&b, &ek, &pk), b"again").expect("seal");
        assert_ne!(second_key, sent_key);
    }

    #[test]
    fn conversation_keys_round_trip_through_their_storage_form() {
        let k = ConversationKey {
            local_instance_id: [0x11; 16],
            peer_node_id: [0x22; 32],
            peer_instance_id: [0x33; 16],
        };
        assert_eq!(ConversationKey::from_storage_key(&k.storage_key()), k);
        assert_eq!(k.storage_key_hex().len(), CONVERSATION_KEY_LEN * 2);
        // Two devices of one contact must not collapse onto one key.
        let other = ConversationKey {
            peer_instance_id: [0x44; 16],
            ..k
        };
        assert_ne!(other.storage_key(), k.storage_key());
    }

    #[test]
    fn corrupt_conversation_blobs_are_refused() {
        let (a, b) = (device(0xB3), device(0xC3));
        a_to_b(&a, &b, b"x").expect("open");
        let key = b.store.keys()[0];
        let good = b.store.export(&key).expect("held");

        let fresh = RatchetStore::new();
        assert!(fresh.import(&key, &[]).is_err(), "empty accepted");
        assert!(
            fresh.import(&key, &good[..good.len() - 1]).is_err(),
            "truncated accepted"
        );
        let mut trailing = good.to_vec();
        trailing.push(0);
        assert!(fresh.import(&key, &trailing).is_err(), "trailing accepted");
        let mut bad_magic = good.to_vec();
        bad_magic[0] = b'X';
        assert!(fresh.import(&key, &bad_magic).is_err(), "bad magic accepted");
        let mut bad_version = good.to_vec();
        bad_version[4] = 9;
        assert!(
            fresh.import(&key, &bad_version).is_err(),
            "bad version accepted"
        );
        assert!(fresh.is_empty(), "no refusal may leave a partial entry");
        fresh.import(&key, &good).expect("the genuine blob imports");
        assert_eq!(fresh.len(), 1);
    }

    #[test]
    fn malformed_payloads_are_refused() {
        let (a, b) = (device(0xB4), device(0xC4));
        let (ek, pk) = (b.ek(), b.ratchet_pk());
        let good = seal(&a.store, &a.me(), keys(&b, &ek, &pk), b"z").expect("seal").0;
        let a_pk = a.ratchet_pk();

        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("empty", vec![]),
            ("header only", good[..HEADER_LEN].to_vec()),
            ("wrong marker", {
                let mut v = good.clone();
                v[0] = veil_proto::E2E_MARKER;
                v
            }),
            ("wrong version", {
                let mut v = good.clone();
                v[1] = 9;
                v
            }),
            ("unknown kind", {
                let mut v = good.clone();
                v[2] = 7;
                v
            }),
            ("truncated prologue", good[..HEADER_LEN + 40].to_vec()),
        ];
        for (name, payload) in cases {
            assert!(
                open(&b.store, &b.me(), &a.node_id, &payload, Some(&a_pk), NOW).is_err(),
                "{name} was accepted"
            );
        }
        assert!(open(&b.store, &b.me(), &a.node_id, &good, Some(&a_pk), NOW).is_ok());
    }

    #[test]
    fn the_transcript_carries_no_signature() {
        // Deniability as a property of the bytes on the wire: a payload is a
        // header, a prologue or nothing, one AEAD blob, and no room for
        // anything else. A signature would show up as length.
        let (a, b) = (device(0xB5), device(0xC5));
        let (ek, pk) = (b.ek(), b.ratchet_pk());
        let plaintext = b"the entire message";
        let first = seal(&a.store, &a.me(), keys(&b, &ek, &pk), plaintext).expect("seal").0;
        // 44 header + 1184 encapsulation key + 16 tag, per the primitive, and
        // the 32-byte delivery-ACK key that rides inside the ciphertext.
        const FRAME_OVERHEAD: usize = 44 + 1184 + 16 + ACK_KEY_LEN;
        assert_eq!(
            first.len(),
            HEADER_LEN + PQXDH_PROLOGUE_LEN + FRAME_OVERHEAD + plaintext.len()
        );
        let a_pk = a.ratchet_pk();
        open(&b.store, &b.me(), &a.node_id, &first, Some(&a_pk), NOW).expect("open");
        let (aek, apk) = (a.ek(), a.ratchet_pk());
        let reply = seal(&b.store, &b.me(), keys(&a, &aek, &apk), b"r").expect("seal").0;
        let b_pk = b.ratchet_pk();
        open(&a.store, &a.me(), &b.node_id, &reply, Some(&b_pk), NOW).expect("open");
        let second = seal(&a.store, &a.me(), keys(&b, &ek, &pk), plaintext).expect("seal").0;
        // A bare frame answering an outstanding ciphertext: 1088 more.
        assert_eq!(
            second.len(),
            HEADER_LEN + FRAME_OVERHEAD + 1088 + plaintext.len()
        );
    }
}
