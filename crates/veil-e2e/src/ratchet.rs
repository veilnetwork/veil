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
/// Re-exported so a caller of [`RatchetStore::skip_send_to`] does not need a
/// direct dependency on `veil-ratchet` just to name its argument.
pub use veil_ratchet::SendPosition;

/// Why a [`skip_send_to`](RatchetStore::skip_send_to) could not be applied.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RatchetSkipError {
    /// The key names nothing this store holds.
    #[error("no conversation under that key")]
    NoConversation,
    /// The ratchet refused the position — see `veil_ratchet::RatchetError`.
    #[error("ratchet refused the position: {0}")]
    Ratchet(String),
}

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

    /// The conversation stopped opening the peer's frames, so it was dropped.
    ///
    /// Distinct from the failure that preceded it because the caller has
    /// something to DO about this one: the peer still believes its session is
    /// fine — nothing tells a sender that its frames are not being opened —
    /// and will keep sending on it forever unless it is told to start over.
    ///
    /// Reached only after [`WEDGED_AFTER_FRAME_FAILURES`] consecutive bare
    /// frames failed against a session we hold. A prologue that fails is NOT
    /// counted: one of those is how a peer legitimately starts over, and
    /// replaying an old one must not be a way to unseat a live conversation.
    #[error("conversation dropped: it stopped opening this peer's frames")]
    WedgedConversationDropped,

    /// The store is at [`MAX_CONVERSATIONS`] and every conversation in it is
    /// one this device has spoken on, so there is nothing that can be dropped
    /// without stranding a live conversation and its peer for good.
    ///
    /// Not reachable by a stranger: everything a stranger can plant is
    /// unproven, and unproven conversations are exactly what the quota
    /// evicts. Reaching this takes a genuine contact list larger than the
    /// ceiling, and the answer is for the host to forget conversations it no
    /// longer wants — refusing one send is recoverable, silently breaking one
    /// of the thousand already held is not.
    #[error("ratchet store is full ({MAX_CONVERSATIONS} conversations, none droppable)")]
    StoreFull,

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
    /// When the certificate these keys came out of stops vouching for them.
    ///
    /// Carried in so the conversation can record HOW LONG the peer is proven
    /// rather than merely that it was, which is what let a revoked device keep
    /// its authenticated standing across restarts (report17 V17-H1). Already
    /// clipped by the verifier to the delegation and document behind it
    /// (V17-H2).
    pub authorized_until_unix: u64,
}

/// Our own half: who we are and what we can decrypt with.
///
/// The two identifiers are held by value, not borrowed: the instance id lives
/// behind a lock in [`RatchetRuntime`] because a device identity can be swapped
/// while the node runs, and 48 bytes is not worth a lifetime.
#[derive(Clone)]
pub struct RatchetIdentity {
    /// Our node id.
    pub local_node_id: [u8; 32],
    /// Which of our devices is speaking.
    pub local_instance_id: [u8; 16],
    /// The ring holding the current mailbox seed and its still-usable
    /// predecessors. Both halves of a certificate come out of it, in matched
    /// order, so a sender working from a week-old certificate still finds the
    /// pair it addressed.
    pub seed_ring: std::sync::Arc<MlKemSeedRing>,
}

impl std::fmt::Debug for RatchetIdentity {
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
/// Blob version. `2` carries the last-used timestamp `1` had no room for;
/// there is no shim, because nothing has shipped.
const CONVERSATION_BLOB_V2: u8 = 2;

/// The most conversations one PEER may hold that this device has never
/// answered.
///
/// Unproven conversations are the ones a stranger can create: they cannot make
/// us seal to them, so every conversation a flood produces is in this class.
/// The global ceiling bounds how many exist; this bounds how many ONE sender
/// can be responsible for, which is what turns "a peer churns the whole store"
/// into "a peer churns eight slots".
///
/// Generous against the honest case it could bite: a contact reaches us from
/// one conversation per device, and the moment we answer any of them it stops
/// being unproven and stops counting here. Eight devices all talking to us
/// before we have said a word back is already an unusual person.
pub const MAX_UNPROVEN_PER_PEER: usize = 8;

/// The most skipped message keys this store banks across ALL conversations.
///
/// `MAX_SKIP_TOTAL` bounds ONE conversation at 2 000, and `MAX_CONVERSATIONS`
/// bounds the count at 1 024 — but 1 024 × 2 000 is two million banked keys,
/// and a banked key is a 32-byte secret in a map node. That is hundreds of
/// megabytes on a device where the whole app has tens, and every one of them
/// is put there by somebody else's frames (report12 V-M10).
///
/// Deliberately NOT a smaller per-conversation cap, which is what the report
/// asks for and what would break the case this store exists to serve: the
/// mailbox hands over up to `MAX_FETCH_COUNT` entries at once and an offline
/// backlog arrives in arbitrary order, so a single conversation legitimately
/// needs its full allowance. This bounds the SUM instead, and 64 000 is
/// thirty-two conversations at their full 2 000 — far past any honest
/// simultaneous backlog, far short of what a flood wants.
pub const MAX_SKIPPED_KEYS_TOTAL: usize = 64_000;

/// The largest number of conversations one device holds at once.
///
/// A ceiling is required because the *inbound* side of this store is driven by
/// strangers: a prologue is sealed to keys we publish, so anyone who can reach
/// this node can make it hold a session, and nothing about that costs the
/// sender more than one encapsulation. Without a ceiling the only bound on our
/// memory is how long an attacker cares to keep sending.
///
/// Sized for the legitimate case with room to spare: the store is per device,
/// and one conversation is one *device* of one contact, so a thousand covers a
/// contact list far larger than a person has, times several devices each.
pub const MAX_CONVERSATIONS: usize = 1_024;

/// How long an UNPROVEN conversation may go unused before it is dropped.
///
/// Measured from last use, not from creation: a conversation that is still
/// carrying traffic is not stale however old it is. Longer than the mailbox's
/// store-and-forward window, so a peer whose prologue is still being
/// retransmitted through the mail is never aged out from under a message that
/// is genuinely in flight.
///
/// It applies to unproven conversations only. See
/// [`RatchetStore::expire`](RatchetStore::expire) for why a proven one has no
/// expiry at all.
pub const UNPROVEN_TTL_SECS: u64 = 14 * 24 * 60 * 60;

/// Consecutive bare frames that must fail against a held session before the
/// conversation is given up as wedged.
///
/// A proven conversation is otherwise permanent, which is right while it works
/// and a trap once it stops: a device re-key, a restored backup or a wire
/// format that moved leaves a session that opens nothing, and it still refuses
/// every prologue that would replace it. Measured on two devices as 48 frames
/// refused in a row with no way back short of reinstalling.
///
/// Small on purpose. Every frame counted here arrived on an AUTHENTICATED
/// session with the peer and still would not open, which a healthy chain does
/// not do even once; the margin is for a reordered or duplicated frame, not for
/// patience.
pub const WEDGED_AFTER_FRAME_FAILURES: u32 = 3;

struct Entry {
    session: RatchetSession,
    /// The peer's device X25519 key this session was keyed to.
    peer_ik: [u8; 32],
    /// How long the evidence that keyed this conversation stays good.
    ///
    /// `0` means nothing has vouched for the key yet. Otherwise it is the
    /// `valid_until` of the certificate that did — clipped, by the verifier,
    /// to the delegation and the document behind it.
    ///
    /// A BIT lived here before, and a bit only ever went up. A device that was
    /// legitimate when the conversation started kept its authenticated
    /// standing after the certificate expired, after the delegation lapsed and
    /// after the owner revoked the device — across restarts too, because the
    /// bit was persisted and restored without asking anything (report17
    /// V17-H1). Whether a session can still DECRYPT is a fact about keys and
    /// does not change; whether the sender may still be shown as proven is a
    /// question about now, and now keeps moving.
    ///
    /// On the side that initiated, this is set from the certificate it read
    /// before deriving anything. On the side that accepted it starts at 0 and
    /// is filled the first time the peer's certificate is in hand.
    authenticated_until: u64,
    /// Was this conversation EVER vouched for, whatever the stamp says now?
    ///
    /// Separate from the stamp because the two answer different questions and
    /// one blob shape can only carry one of them. A build older than the stamp
    /// wrote a bare bit: "proven once, cannot say for how long". Restoring
    /// that as `authenticated_until = 0` is right and is what stops a bit
    /// outliving a revocation — but it also made [`Self::ever_proven`] false,
    /// and that is the question EVICTION asks. So an upgrade turned a proven
    /// conversation into a droppable one, and the doc on `ever_proven` says in
    /// as many words that this must not happen (report18 V18-H1).
    ///
    /// Costs nothing in the format: the byte this is written to is the same
    /// one the bit was always written to, so an older reader sees what it
    /// always saw.
    proven_before: bool,
    /// The PQXDH prologue to re-attach to outgoing frames until the peer
    /// answers. `None` once anything of theirs has opened.
    pending_prologue: Option<Vec<u8>>,
    /// Consecutive frames that failed to open against this session. Reset by
    /// any success, in memory only — never encoded, so a restart forgives.
    ///
    /// A REPLAY of the prologue this entry was built from is never counted:
    /// duplicate delivery of one prologue is ordinary on a lossy network, and
    /// treating it as evidence would let a recorded prologue unseat a live
    /// conversation. Anything else that will not open is real evidence — a bare
    /// frame from a chain that moved on, or a NEW prologue, which is the peer
    /// saying it has started over.
    frame_failures: u32,
    /// The prologue this conversation was built from, kept so a replay of it
    /// can be told from a peer genuinely re-keying. In memory only.
    accepted_prologue: Option<Vec<u8>>,
    /// Local unix seconds at the last message this conversation carried, in
    /// either direction. Persisted, so a restart does not make every stale
    /// conversation look fresh — on a phone that would mean the sweep below
    /// never fires at all.
    ///
    /// Only *successful* work moves it. A forged frame aimed at a conversation
    /// must not be able to keep it alive, or the eviction order becomes
    /// something an attacker writes.
    last_used_at: u64,
}

impl Entry {
    /// Whether the quota and the sweep may take this conversation.
    ///
    /// The rule is one bit wide on purpose, and it is not "least recently
    /// used". What makes an entry safe to drop is that **we have never sent a
    /// message on it**, and `authenticated` is exactly that fact: every path
    /// that seals into a conversation settles it against a verified
    /// certificate first, so a conversation we have spoken on is proven, and a
    /// conversation that is not proven is one we have never answered.
    ///
    /// That matters because the peer's copy is then still holding its PQXDH
    /// prologue — it stops re-attaching it only when something of ours opens —
    /// so the peer re-opens the conversation on its very next message and
    /// nothing is stranded. Drop a *proven* one and the opposite happens: the
    /// peer's side is proven and answered, [`open`]'s displacement rule
    /// (correctly) refuses to let any prologue re-key it, and both ends are
    /// stuck for good with no message on the wire that could recover them.
    /// Is the peer PROVEN, as of `now`?
    ///
    /// Never "was it ever": that is the question the persisted bit answered,
    /// and the answer outlived every way an owner has of taking a device away.
    fn is_authenticated(&self, now_unix: u64) -> bool {
        self.authenticated_until != 0 && now_unix <= self.authenticated_until
    }

    /// Has anything EVER vouched for this key?
    ///
    /// Deliberately not the same question as [`Self::is_authenticated`], and
    /// this is what eviction and displacement ask. A conversation whose
    /// evidence has merely gone stale still decrypts, still belongs to the
    /// peer it was agreed with, and must not become a slot an inbound prologue
    /// may take — that would turn every expiry into an opening for a stranger.
    /// What expiry costs is standing, not the session.
    fn ever_proven(&self) -> bool {
        self.authenticated_until != 0 || self.proven_before
    }

    fn droppable(&self) -> bool {
        !self.ever_proven()
    }

    fn encode(&self) -> Zeroizing<Vec<u8>> {
        let session = self.session.export_state();
        let prologue = self.pending_prologue.as_deref().unwrap_or(&[]);
        let mut out =
            Vec::with_capacity(4 + 1 + 32 + 1 + 8 + 1 + 2 + prologue.len() + 4 + session.len());
        out.extend_from_slice(&CONVERSATION_BLOB_MAGIC);
        out.push(CONVERSATION_BLOB_V2);
        out.extend_from_slice(&self.peer_ik);
        // The byte stays where it was, and still says only "was there ever
        // evidence" — a build that predates the stamp reads this file and gets
        // the same answer it always did.
        out.push(u8::from(self.ever_proven()));
        out.extend_from_slice(&self.last_used_at.to_be_bytes());
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
        // Appended LAST, after the session.
        //
        // THE V2 LAYOUT IS CLOSED. Appending was free exactly once, because
        // the reader that refuses trailing bytes and the reader that tolerates
        // this stamp are the same one and shipped together — no released build
        // ever saw a V2 blob with a suffix it did not know. The next field is
        // not free: every build from v0.10.0 onward rejects a longer V2 blob
        // outright ("trailing bytes in conversation blob"), so a downgrade
        // after it would find every conversation on the device unreadable.
        // Add one by bumping to a V3 tag and teaching THIS reader to accept
        // both — never by extending V2 again (report20 V18-M11).
        out.extend_from_slice(&self.authenticated_until.to_be_bytes());
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
        if version != CONVERSATION_BLOB_V2 {
            return Err(RatchetSpliceError::UnsupportedVersion(version));
        }
        let mut peer_ik = [0u8; 32];
        peer_ik.copy_from_slice(take(32)?);
        let ever_authenticated = match take(1)?[0] {
            0 => false,
            1 => true,
            _ => return Err(RatchetSpliceError::Malformed("bad boolean")),
        };
        let last_used_at = u64::from_be_bytes(
            take(8)?
                .try_into()
                .map_err(|_| RatchetSpliceError::Malformed("last-used timestamp"))?,
        );
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
        // Written by a build that had only the bit. It said this peer was
        // proven ONCE and cannot say for how long, so the conversation is
        // restored able to decrypt and NOT proven: the next certificate in
        // hand fills the stamp in, and until then a sender is shown as what it
        // can be shown to be. Demoting is the direction that cannot be wrong.
        // Last use of the reader, so the borrow it holds on the cursor ends
        // here and the trailing-bytes check below can read it.
        let stamp = take(8).ok().map(<[u8; 8]>::try_from);
        let authenticated_until = match stamp {
            None => 0,
            Some(Ok(bytes)) => u64::from_be_bytes(bytes),
            Some(Err(_)) => {
                return Err(RatchetSpliceError::Malformed("authorization stamp"));
            }
        };
        if at != bytes.len() {
            return Err(RatchetSpliceError::Malformed(
                "trailing bytes in conversation blob",
            ));
        }
        Ok(Self {
            session,
            peer_ik,
            authenticated_until,
            proven_before: ever_authenticated,
            pending_prologue,
            last_used_at,
            // Never encoded: a restart forgives a wedged conversation anyway.
            frame_failures: 0,
            accepted_prologue: None,
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

    /// Drop every unproven conversation idle for longer than the TTL.
    ///
    /// Idleness is `now_unix - last_used_at` under a saturating subtraction, so
    /// a clock that steps backwards makes conversations look *younger* and
    /// nothing is dropped. That is the safe direction: the cost of aging one
    /// out early is a message the peer has to resend, and the cost of keeping
    /// one too long is a slot the quota below will reclaim anyway.
    fn expire(&mut self, now_unix: u64) -> usize {
        let stale: Vec<ConversationKey> = self
            .entries
            .iter()
            .filter(|(_, e)| {
                e.droppable() && now_unix.saturating_sub(e.last_used_at) > UNPROVEN_TTL_SECS
            })
            .map(|(k, _)| *k)
            .collect();
        for key in &stale {
            self.entries.remove(key);
            // Marked, not silently dropped: the host is holding a blob for
            // this conversation and has to be told to delete it, or the next
            // launch imports exactly what we just aged out.
            self.commit_change(*key);
        }
        stale.len()
    }

    /// Bring the banked skipped keys back under [`MAX_SKIPPED_KEYS_TOTAL`].
    ///
    /// Swept from UNPROVEN conversations only, largest bank first, with the
    /// same operation the import path already uses: keys from epochs the chain
    /// has moved past. A conversation this device has spoken on keeps its bank
    /// whole — the quota must not become a way to make somebody else's
    /// messages unreadable, which is the same rule `make_room` follows.
    ///
    /// Returns how many keys went, and marks whatever it touched: what is held
    /// is now smaller than what is on disk.
    fn enforce_skipped_budget(&mut self) -> usize {
        self.enforce_skipped_budget_to(MAX_SKIPPED_KEYS_TOTAL)
    }

    /// [`enforce_skipped_budget`](Self::enforce_skipped_budget) against an
    /// explicit ceiling.
    ///
    /// The budget is a parameter rather than a constant read inside so a test
    /// can drive the policy — which entries are swept and which are spared —
    /// without banking sixty-four thousand keys to reach the real one.
    fn enforce_skipped_budget_to(&mut self, budget: usize) -> usize {
        let total: usize = self.entries.values().map(|e| e.session.skipped_len()).sum();
        if total <= budget {
            return 0;
        }
        let mut freed = 0;
        loop {
            let victim = self
                .entries
                .iter()
                .filter(|(_, e)| e.droppable() && e.session.skipped_len() > 0)
                .max_by_key(|(k, e)| (e.session.skipped_len(), **k))
                .map(|(k, _)| *k);
            let Some(key) = victim else { break };
            let Some(entry) = self.entries.get_mut(&key) else {
                break;
            };
            // The gentle sweep first: keys from epochs the chain has moved
            // past cost nothing to lose. It is not enough on its own — a
            // flood fills the CURRENT epoch, which that sweep keeps — so a
            // bank still standing after it is cleared outright. Only for a
            // conversation this device has never answered: for one it has,
            // the same act would make a real correspondent unreadable.
            let mut dropped = entry.session.prune_skipped_to_current_epoch();
            if dropped == 0 {
                dropped = entry.session.clear_skipped();
            }
            if dropped == 0 {
                break;
            }
            freed += dropped;
            self.commit_change(key);
            if total - freed.min(total) <= budget {
                break;
            }
        }
        freed
    }

    /// Make room for one more conversation. `false` when there is none.
    ///
    /// Aging out comes first and eviction second, so a store that is merely
    /// stale loses nothing that is still in use. Eviction takes the
    /// least-recently-used *droppable* entry and only ever one, and both
    /// steps are confined to conversations we have never sent on — see
    /// [`Entry::droppable`]. That is what keeps the quota from becoming a
    /// weapon: a stranger's conversations are unproven by construction (they
    /// cannot make us seal to them, and they cannot produce a prologue that
    /// announces the key a contact published and still opens), so however many
    /// a flood creates, every one of them is in the class the next admission
    /// evicts, and not one proven conversation moves.
    fn make_room(&mut self, incoming: &ConversationKey, now_unix: u64) -> bool {
        // One peer may not churn the whole store.
        //
        // A stranger's conversations are unproven by construction, so eviction
        // never touches a proven one — that part already held. What did not is
        // the COST of the churn: by varying its instance id, a single reachable
        // sender takes every unproven slot in turn, and each eviction costs the
        // host a blob delete and the scrub that follows it (report12 V-M10).
        //
        // Confining a peer to its own quota makes that cost proportional to the
        // number of distinct peers rather than to how fast one of them can
        // rename itself. It is checked BEFORE the ceiling, so the peer at its
        // quota recycles its own slot even in a store with room to spare, and
        // never reaches the global victim at all.
        let mut mine: Vec<(u64, ConversationKey)> = self
            .entries
            .iter()
            .filter(|(k, e)| k.peer_node_id == incoming.peer_node_id && e.droppable())
            .map(|(k, e)| (e.last_used_at, *k))
            .collect();
        if mine.len() >= MAX_UNPROVEN_PER_PEER {
            mine.sort_unstable();
            let (_, oldest) = mine[0];
            self.entries.remove(&oldest);
            self.commit_change(oldest);
            return true;
        }
        if self.entries.len() < MAX_CONVERSATIONS {
            return true;
        }
        self.expire(now_unix);
        if self.entries.len() < MAX_CONVERSATIONS {
            return true;
        }
        // `min_by_key` over `(last_used_at, key)` rather than `last_used_at`
        // alone: two conversations can share a second, and which one goes has
        // to be a property of the store and not of the map's traversal.
        let victim = self
            .entries
            .iter()
            .filter(|(_, e)| e.droppable())
            .min_by_key(|(k, e)| (e.last_used_at, **k))
            .map(|(k, _)| *k);
        match victim {
            Some(key) => {
                self.entries.remove(&key);
                self.commit_change(key);
                true
            }
            // Every conversation held is one we have spoken on. Refusing is
            // the only safe answer left: taking one would strand it and its
            // peer permanently, and there is no attacker-reachable path to
            // this state — only a user with more live conversations than the
            // ceiling allows.
            None => false,
        }
    }
}

/// Every ratchet conversation this node currently holds, in memory.
///
/// The store is the thing the host persists. It is deliberately *not* a cache:
/// evicting an entry does not cost a round trip, it costs every message the
/// peer sends afterwards, because the chain cannot be rebuilt from anything
/// public.
///
/// Which is why it holds two classes of entry and treats them as different
/// things. A conversation this device has **spoken on** leaves only when the
/// host says so ([`forget`](Self::forget)) — nothing here drops one, at any
/// age, under any pressure, because the peer's side cannot be restarted by
/// anything on the wire and dropping ours would strand both. A conversation
/// somebody opened that we have **never answered** is the other class, and it
/// is the one an attacker can create at will: a prologue is sealed to keys we
/// publish, so anyone who can reach this node can make it hold state. Those
/// age out ([`expire`](Self::expire)) and are evicted under the
/// [`MAX_CONVERSATIONS`] ceiling, and losing one costs nothing, because the
/// peer is still holding the prologue that re-opens it.
///
/// [`Entry::droppable`] is where that line is drawn and why it lands there.
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
    ///
    /// Bounded by [`MAX_CONVERSATIONS`], so this cannot grow without limit —
    /// but it is still the whole set in one allocation, and a host that walks
    /// it to save state holds the lock for the length of the walk. Prefer
    /// [`keys_after`](Self::keys_after), which costs the page and not the
    /// store.
    #[must_use]
    pub fn keys(&self) -> Vec<ConversationKey> {
        self.lock().entries.keys().copied().collect()
    }

    /// One page of conversation keys, in key order, starting strictly after
    /// `after`. `None` starts at the beginning.
    ///
    /// The cursor is the last key of the previous page, and it is a *key*
    /// rather than an offset for the reason offsets are wrong here: the store
    /// mutates between pages — a conversation is opened, another is evicted —
    /// and an offset would then skip or repeat whatever moved across it. A key
    /// cursor cannot: the walk resumes at the same point in the ordering
    /// whether or not the entry it names is still held. A page shorter than
    /// `max` is the end of the walk.
    ///
    /// Costs `O(log n + page)`, so a full pass is linear in the store rather
    /// than quadratic, and each page holds the lock only for its own length.
    #[must_use]
    pub fn keys_after(&self, after: Option<&ConversationKey>, max: usize) -> Vec<ConversationKey> {
        use std::ops::Bound;
        let g = self.lock();
        match after {
            Some(cursor) => g
                .entries
                .range((Bound::Excluded(*cursor), Bound::Unbounded))
                .map(|(k, _)| *k)
                .take(max)
                .collect(),
            None => g.entries.keys().take(max).copied().collect(),
        }
    }

    /// Drop every unproven conversation idle for longer than
    /// [`UNPROVEN_TTL_SECS`], and mark each so the host deletes its blob.
    /// Returns how many went.
    ///
    /// `now_unix` must come from the local clock. Nothing a peer says about
    /// the time reaches this decision, and nothing should be made to: a value
    /// from the wire would let whoever supplied it choose which of our
    /// conversations are old enough to disappear.
    ///
    /// **A proven conversation has no expiry, at any age.** Not an oversight
    /// and not a tuning choice — there is no safe way to age one out. Dropping
    /// it leaves the peer holding a proven, answered session, and [`open`]'s
    /// displacement rule refuses to let any prologue re-key one of those,
    /// precisely so a stranger cannot reset a live conversation by replaying
    /// or forging one. So our fresh prologue is refused, their next frame
    /// arrives at a store that has nothing to open it with, and the two ends
    /// are wedged with no message either could send to recover. What bounds
    /// the proven class is the ceiling and the host's own
    /// [`forget`](Self::forget), which knows what the user still wants.
    pub fn expire(&self, now_unix: u64) -> usize {
        self.lock().expire(now_unix)
    }

    /// The ceiling this store enforces, for a host sizing its own buffers.
    #[must_use]
    pub fn capacity(&self) -> usize {
        MAX_CONVERSATIONS
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

    /// Where a conversation's sending chain stands.
    ///
    /// Small enough for the host to write durably BEFORE it publishes a
    /// ciphertext — 36 bytes against the state's kilobytes — which is what
    /// makes the guarantee affordable on the send path (report12 X-H5).
    ///
    /// `None` when the key names nothing held, or when the conversation has
    /// no sending chain yet and so has no position to reserve.
    #[must_use]
    pub fn send_position(&self, key: &ConversationKey) -> Option<veil_ratchet::SendPosition> {
        self.lock()
            .entries
            .get(key)
            .and_then(|e| e.session.send_position())
    }

    /// Step a conversation's sending chain past every index that might
    /// already have been spent, and report how many were burned.
    ///
    /// The recovery half of [`send_position`](Self::send_position): a state
    /// restored from before an unwritten send is fast-forwarded to the last
    /// position the host recorded, so no key it may already have published
    /// under can come round again.
    ///
    /// Marks the conversation dirty when it actually moves — the chain
    /// changed, and a state left unwritten would be behind again on the next
    /// start, which is where this began.
    pub fn skip_send_to(
        &self,
        key: &ConversationKey,
        to: veil_ratchet::SendPosition,
    ) -> Result<u32, RatchetSkipError> {
        let mut guard = self.lock();
        let entry = guard
            .entries
            .get_mut(key)
            .ok_or(RatchetSkipError::NoConversation)?;
        let burned = entry
            .session
            .skip_send_to(to)
            .map_err(|e| RatchetSkipError::Ratchet(e.to_string()))?;
        if burned > 0 {
            guard.version += 1;
            let version = guard.version;
            guard.dirty.insert(*key, version);
        }
        Ok(burned)
    }

    /// Put a conversation back, from bytes [`export`](Self::export) produced.
    ///
    /// Replaces whatever is held under that key. Importing does not mark the
    /// conversation dirty — the host just read it, so writing it straight back
    /// would be pointless — but it does advance
    /// [`version`](Self::version), because the store's contents changed.
    ///
    /// Subject to the same quota as everything else, and for the same reason:
    /// a host's own on-disk set is not trustworthy input either — it is where
    /// yesterday's flood was persisted to. Hydrating a store that outgrew the
    /// ceiling ages out and evicts by the rules in
    /// [`Entry::droppable`], and returns [`StoreFull`](RatchetSpliceError::StoreFull)
    /// only when every conversation held is one this device has spoken on.
    /// Restoring over a key already held always fits: nothing grows.
    ///
    /// `now_unix` is the local clock, and is used only to decide what is stale.
    pub fn import(
        &self,
        key: &ConversationKey,
        blob: &[u8],
        now_unix: u64,
    ) -> Result<(), RatchetSpliceError> {
        let mut entry = Entry::decode(blob)?;
        // Sweep the skipped-key bank on the way in. The step rule keeps two
        // epochs but only runs when a step runs, and a peer that stopped
        // answering never causes one — so its bank stays fat while our own
        // sends keep rewriting the whole state around it. Restoring is the
        // quiet moment to sweep: once per conversation per session, off every
        // hot path. Measured before this existed: 324 banked keys spanning 42
        // epochs, in a 23 KB state rewritten on every advance.
        let dropped = entry.session.prune_skipped_to_current_epoch();
        let mut g = self.lock();
        if !g.entries.contains_key(key) && !g.make_room(key, now_unix) {
            return Err(RatchetSpliceError::StoreFull);
        }
        g.entries.insert(*key, entry);
        g.version = g.version.wrapping_add(1);
        // An import does NOT normally mark the conversation dirty — the host
        // just read those bytes, so writing them straight back is pointless.
        // A sweep changes that: what is now held is smaller than what is on
        // disk, and only a mark gets the smaller version written.
        if dropped > 0 {
            g.commit_change(*key);
        }
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
///
/// `now_unix` is the local clock. It is what this conversation's last-use
/// stamp is set to, and nothing a peer sends contributes to it.
pub fn seal(
    store: &RatchetStore,
    me: &RatchetIdentity,
    peer: PeerRatchetKeys<'_>,
    app_payload: &[u8],
    now_unix: u64,
) -> Result<(Vec<u8>, [u8; ACK_KEY_LEN]), RatchetSpliceError> {
    let mut ack_key = [0u8; ACK_KEY_LEN];
    OsRatchetRng.fill_bytes(&mut ack_key);
    let mut plaintext = Zeroizing::new(Vec::with_capacity(ACK_KEY_LEN + app_payload.len()));
    plaintext.extend_from_slice(&ack_key);
    plaintext.extend_from_slice(app_payload);
    seal_inner(store, me, peer, &plaintext, now_unix).map(|payload| (payload, ack_key))
}

fn seal_inner(
    store: &RatchetStore,
    me: &RatchetIdentity,
    peer: PeerRatchetKeys<'_>,
    plaintext: &[u8],
    now_unix: u64,
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
        .map(|e| (e.peer_ik == *peer.ratchet_pk, e.is_authenticated(now_unix)))
        && !proven
    {
        if matches_certificate {
            // The announcement was true. Only the holder of that key's secret
            // could have agreed the root this conversation runs on, so the
            // peer is proven from here on and a later rotation of theirs must
            // not be read as a contradiction.
            if let Some(entry) = g.entries.get_mut(&key) {
                // For as long as the certificate we just checked says so, and
                // no longer.
                entry.authenticated_until = peer.authorized_until_unix;
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
            entry.last_used_at = now_unix;
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
            // Room before work: the key agreement below is the expensive part,
            // and a store with nothing droppable in it is not going to hold the
            // result anyway.
            if !g.make_room(&key, now_unix) {
                return Err(RatchetSpliceError::StoreFull);
            }
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
                    // caller verified — proven from the reply on, and only for
                    // as long as that certificate is good for.
                    authenticated_until: peer.authorized_until_unix,
                    // A fresh conversation is proven exactly as far as its
                    // stamp says; nothing older is being restored here.
                    proven_before: false,
                    pending_prologue: Some(blob[..PQXDH_PROLOGUE_LEN].to_vec()),
                    last_used_at: now_unix,
                    frame_failures: 0,
                    accepted_prologue: None,
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
/// `peer_devices` are the device X25519 keys that peer's verified certificates
/// carry, when the caller has them. They decide two things, and both of them
/// the same way — by whether the key a prologue announces is one the peer
/// published:
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
    me: &RatchetIdentity,
    sender_node_id: &[u8; 32],
    payload: &[u8],
    peer_devices: Option<&PeerDeviceKeys>,
    now_unix: u64,
) -> Result<Opened, RatchetSpliceError> {
    let mut opened = open_inner(store, me, sender_node_id, payload, peer_devices, now_unix)?;
    if opened.plaintext.len() < ACK_KEY_LEN {
        // Authenticated, so it came from the peer — but the peer built a
        // payload this version does not understand. Refuse rather than hand a
        // truncated application payload upward.
        return Err(RatchetSpliceError::Malformed(
            "plaintext shorter than its ack key",
        ));
    }
    let rest = opened.plaintext.split_off(ACK_KEY_LEN);
    opened
        .ack_key
        .copy_from_slice(&std::mem::replace(&mut opened.plaintext, rest));
    Ok(opened)
}

fn open_inner(
    store: &RatchetStore,
    me: &RatchetIdentity,
    sender_node_id: &[u8; 32],
    payload: &[u8],
    peer_devices: Option<&PeerDeviceKeys>,
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
    // holder of its secret can have built a frame that decrypts.
    //
    // The device is asked for as well as the key, and that is not belt and
    // braces. Holding the secret proves WHO, and a certificate binds that key
    // to one device of theirs; without the second half, a contact whose key we
    // verified once could mint an authenticated conversation per made-up
    // sender instance, and authenticated conversations are the ones eviction
    // may not touch (report15 V15-M5). A device that genuinely changes its
    // instance publishes a certificate saying so, and re-resolving it restores
    // the pair — so this heals rather than latches.
    let proves_authorship = message.as_ref().is_some_and(|m| {
        peer_devices.is_some_and(|d| d.contains(&sender_instance_id, m.initiator_ik(), now_unix))
    });

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
        |e: &Entry| proves_authorship && (!e.ever_proven() || e.pending_prologue.is_some());

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
                    // Opening again — whatever streak there was is history.
                    entry.frame_failures = 0;
                    // Only here, after the tag verified. A frame that failed
                    // moved nothing else and must not move this either, or the
                    // eviction order becomes something an attacker writes by
                    // aiming garbage at whichever conversation it wants kept.
                    entry.last_used_at = now_unix;
                    // Refreshed on EVERY frame that opens, not only the first
                    // time. The stamp is the certificate's, so a peer that
                    // re-published moves it forward and a peer whose
                    // certificate lapsed lets it run out — which is the whole
                    // difference between asking "was this ever proven" and
                    // "is it proven now".
                    if let Some(until) = peer_devices
                        .and_then(|d| d.authorized_until(&sender_instance_id, &entry.peer_ik))
                    {
                        entry.authenticated_until = entry.authenticated_until.max(until);
                    }
                    let authenticated = entry.is_authenticated(now_unix);
                    g.commit_change(key);
                    // A frame that opened may have banked keys for the ones it
                    // arrived ahead of. Checked HERE, after the tag verified,
                    // for the same reason `last_used_at` moves here: a frame
                    // that failed must not be able to drive this either.
                    // The count is returned rather than logged: this crate
                    // has no logger, and a sweep is visible in the dirty marks
                    // it leaves behind anyway.
                    let _swept = g.enforce_skipped_budget();
                    return Ok(Opened {
                        plaintext,
                        ack_key: [0u8; ACK_KEY_LEN],
                        key,
                        authenticated,
                    });
                }
                Err(e) => {
                    // A BARE FRAME that will not open is the evidence that this
                    // session and the peer's have come apart — a prologue that
                    // fails is not, because starting over is exactly what a
                    // prologue is for.
                    //
                    // Nothing tells a SENDER that its frames are not being
                    // opened, so without this the peer keeps sending on a
                    // session nobody can read, forever. Give the conversation
                    // up and say so; the caller's answer is what gets the peer
                    // to start over.
                    let is_replay_of_our_own = kind == KIND_PROLOGUE
                        && entry
                            .accepted_prologue
                            .as_deref()
                            .is_some_and(|p| blob.len() >= p.len() && &blob[..p.len()] == p);
                    if !is_replay_of_our_own {
                        entry.frame_failures = entry.frame_failures.saturating_add(1);
                        if entry.frame_failures >= WEDGED_AFTER_FRAME_FAILURES {
                            g.entries.remove(&key);
                            g.commit_change(key);
                            return Err(RatchetSpliceError::WedgedConversationDropped);
                        }
                    }
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
                let authenticated_until = peer_devices
                    .and_then(|d| d.authorized_until(&sender_instance_id, &peer_ik))
                    .unwrap_or(0);
                let authenticated = authenticated_until != 0 && now_unix <= authenticated_until;
                let mut g = store.lock();
                // Ask the store again. Another thread may have opened this
                // conversation while the agreement above ran unlocked, and the
                // same rule decides now as decided then: a conversation that is
                // proven and answered is not overwritten. The message opened
                // regardless, so it is genuine and still goes up — it is only
                // the session that is dropped, in favour of the one already
                // held.
                // Displacing an existing entry needs no room — the count does
                // not move — so the quota is asked only when this would be a
                // new conversation. A store with nothing droppable left simply
                // does not keep the session: the message opened and still goes
                // up, because refusing to *read* a genuine message would be a
                // worse answer than refusing to remember the conversation.
                let admit = match g.entries.get(&key) {
                    // Replacing one we hold: allowed, and costs no room.
                    Some(e) if displaceable(e) => Some(true),
                    // Proven and answered. Untouchable, as it was before.
                    Some(_) => None,
                    // A conversation we do not have. This one has to fit.
                    None => Some(false),
                };
                if let Some(replaces) = admit
                    && (replaces || g.make_room(&key, now_unix))
                {
                    g.entries.insert(
                        key,
                        Entry {
                            session,
                            peer_ik,
                            authenticated_until,
                            proven_before: false,
                            pending_prologue: None,
                            last_used_at: now_unix,
                            frame_failures: 0,
                            // Reached only down the prologue path, so this IS
                            // the prologue the conversation was built from.
                            accepted_prologue: Some(blob[..PQXDH_PROLOGUE_LEN].to_vec()),
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
                if first_err.is_none()
                    || matches!(e, RatchetSpliceError::Ratchet(RatchetError::PqDowngrade))
                {
                    first_err = Some(e);
                }
            }
        }
    }
    Err(first_err.unwrap_or(RatchetSpliceError::Ratchet(RatchetError::AuthFailed)))
}

// ── Peer ratchet-key directory ───────────────────────────────────────────────

/// The device X25519 keys one peer's verified certificates have published.
///
/// A SET, and that is the fix rather than an optimisation. A certificate is
/// per DEVICE, so a peer with a phone and a laptop publishes two of these —
/// and this held one key per NODE, so whichever sibling's certificate resolved
/// last overwrote the other. An authentic prologue from the overwritten device
/// then failed the comparison and was filed as unauthenticated, which costs
/// that conversation its claim on the slot and can cost the message its place
/// (report14 V14-M6).
///
/// Membership is the question being asked — "is this key one this identity
/// published?" — and the answer is as true of the second device as the first.
/// Retired keys stay in for the same reason the seed ring keeps retired
/// secrets: a peer working from a certificate we resolved last week announced
/// the key that was current then.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeerDeviceKeys {
    /// Newest first, each key paired with the instance the certificate that
    /// carried it named. Small and linear on purpose: it is at most
    /// [`Self::MAX`] entries and a scan beats a hash on every one of them.
    ///
    /// The instance is half the fact, not decoration. A certificate says "this
    /// DEVICE of this identity publishes this key", and dropping the device
    /// left the weaker statement "this identity published this key somewhere" —
    /// which one verified key turns into an unlimited supply of authenticated
    /// conversations, one per made-up sender instance (report15 V15-M5).
    ///
    /// The third field is WHEN the certificate stops saying it. Verification
    /// checks validity once, at resolve time, and this cache is what the
    /// receive path consults afterwards — so a key from a certificate that has
    /// since expired went on authenticating conversations for as long as the
    /// process lived, and the authenticated bit is persisted, so it outlived
    /// that too (report16 V16-H1).
    keys: Vec<([u8; 16], [u8; 32], u64)>,
}

impl PeerDeviceKeys {
    /// Devices-times-rotations kept for one peer.
    ///
    /// Bounds what one peer costs, and generously against the honest case: an
    /// identity with eight devices, or one device that rotated eight times
    /// since we last spoke, still authenticates.
    pub const MAX: usize = 8;

    /// Record a key from a verified certificate, with the device it named and
    /// the moment that certificate stops saying so. Newest wins the room.
    pub fn remember(&mut self, instance_id: [u8; 16], key: [u8; 32], valid_until: u64) {
        if let Some(at) = self
            .keys
            .iter()
            .position(|(i, k, _)| *i == instance_id && *k == key)
        {
            self.keys.remove(at);
        }
        self.keys.insert(0, (instance_id, key, valid_until));
        self.keys.truncate(Self::MAX);
    }

    /// Whether `key` came from a certificate this peer published FOR THIS
    /// DEVICE.
    ///
    /// All three, because the certificate binds all three. Asking only about
    /// the key answers a question nobody needs: any device of this identity,
    /// which is precisely the licence to invent instances. And asking without
    /// `now` answers a question about the past: a certificate said this once,
    /// and it may have stopped saying it since.
    #[must_use]
    pub fn contains(&self, instance_id: &[u8; 16], key: &[u8; 32], now_unix: u64) -> bool {
        self.authorized_until(instance_id, key)
            .is_some_and(|until| now_unix <= until)
    }

    /// When the certificate that named this (device, key) pair stops saying
    /// so, or `None` if none did.
    ///
    /// The conversation keeps this rather than a bit, so "proven" can stop
    /// being true the way the certificate behind it does (report17 V17-H1).
    #[must_use]
    pub fn authorized_until(&self, instance_id: &[u8; 16], key: &[u8; 32]) -> Option<u64> {
        self.keys
            .iter()
            .find(|(i, k, _)| i == instance_id && k == key)
            .map(|(_, _, until)| *until)
    }

    /// The most recently published key, for callers that need ONE — a
    /// diagnostic, or a readiness check.
    #[must_use]
    pub fn newest(&self) -> Option<[u8; 32]> {
        self.keys.first().map(|(_, k, _)| *k)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }
}

/// `peer_node_id → the device keys that peer's verified certificates carry`.
///
/// The exact counterpart of [`PeerMlKemCache`](crate::PeerMlKemCache), written
/// by whatever resolves and verifies certificates and read on the receive path,
/// which is synchronous and cannot walk a DHT. A miss costs authentication for
/// that one message, never readability.
pub type PeerRatchetKeyCache = std::collections::HashMap<[u8; 32], PeerDeviceKeys>;

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
    ///
    /// Behind a lock for the same reason `local_instance_id` is: a deniable
    /// boot starts under a placeholder identity and is PROMOTED to the real
    /// one while the node runs. This used to be a snapshot taken once at
    /// construction, so after a promotion the node published one identity's
    /// keys and opened with the placeholder's — every peer sealed to something
    /// this node could not decapsulate, and every direct frame failed
    /// authentication for the life of the process.
    pub seed_ring: std::sync::Arc<std::sync::RwLock<std::sync::Arc<MlKemSeedRing>>>,
    /// Our node id — swapped by the same promotion, for the same reason.
    pub local_node_id: std::sync::Arc<std::sync::RwLock<[u8; 32]>>,
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
    /// Re-point this runtime at the identity now in force.
    ///
    /// A deniable boot runs under a placeholder and is promoted later. Before
    /// this existed the ring was a snapshot taken at construction, so after a
    /// promotion the node published one identity's keys and opened with the
    /// placeholder's: peers sealed to a key it could not decapsulate and every
    /// direct frame failed authentication, silently, for the life of the
    /// process. `local_instance_id` already followed the swap; these two are
    /// the rest of the same identity and have to follow it together.
    pub fn adopt_identity(&self, node_id: [u8; 32], ring: std::sync::Arc<MlKemSeedRing>) {
        *self
            .local_node_id
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = node_id;
        *self
            .seed_ring
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = ring;
    }

    /// Our half of a conversation, or `None` when this node has no device
    /// identity to speak as and therefore nothing a peer could address.
    #[must_use]
    pub fn identity(&self) -> Option<RatchetIdentity> {
        let instance = (*self
            .local_instance_id
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner))?;
        Some(RatchetIdentity {
            local_node_id: *self
                .local_node_id
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            local_instance_id: instance,
            seed_ring: std::sync::Arc::clone(
                &self
                    .seed_ring
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner),
            ),
        })
    }

    /// The device key `peer` published, if a verified certificate for them has
    /// been resolved. `None` costs authentication for one message, never
    /// readability.
    #[must_use]
    /// Drop every conversation held with this peer, so the next thing sealed
    /// for them starts a new key agreement.
    ///
    /// The answer to a peer saying our frames no longer open at their end. We
    /// cannot verify that claim — it arrives unauthenticated — and do not need
    /// to: the cost of believing a false one is a single extra prologue, while
    /// the cost of ignoring a true one is a conversation that never recovers.
    ///
    /// Returns how many were dropped.
    pub fn forget_peer(&self, peer_node_id: &[u8; 32]) -> usize {
        let keys: Vec<_> = {
            let g = self.store.lock();
            g.entries
                .keys()
                .filter(|k| &k.peer_node_id == peer_node_id)
                .copied()
                .collect()
        };
        keys.iter().filter(|k| self.store.forget(k)).count()
    }

    /// Diagnostic: is a conversation with this peer stored, and has it ever
    /// opened anything?
    ///
    /// Having been proven is what makes a conversation untouchable by an
    /// inbound prologue (see `displaceable` in [`open`]), so when frames from
    /// a peer stop opening it is the one fact that says whether the
    /// conversation can still recover or is wedged for good. Read-only, no key
    /// material.
    ///
    /// EVER proven, not proven now: the caller is asking whether a prologue
    /// could rescue this conversation, and the answer to that does not change
    /// when a certificate lapses. What lapsing changes is the provenance shown
    /// for a message, which is [`Opened::authenticated`].
    pub fn peer_entry_authenticated(&self, peer_node_id: &[u8; 32]) -> Option<bool> {
        let g = self.store.lock();
        g.entries
            .iter()
            .find(|(k, _)| &k.peer_node_id == peer_node_id)
            .map(|(_, e)| e.ever_proven())
    }

    /// The most recent device key this peer published, for callers that need
    /// ONE — a readiness check, a diagnostic. Authentication asks
    /// [`peer_devices`](Self::peer_devices) instead: a peer has one key PER
    /// DEVICE and any of them proves the identity.
    pub fn published_ik(&self, peer_node_id: &[u8; 32]) -> Option<[u8; 32]> {
        self.peer_devices(peer_node_id).and_then(|d| d.newest())
    }

    /// Every device key this peer's verified certificates have carried.
    #[must_use]
    pub fn peer_devices(&self, peer_node_id: &[u8; 32]) -> Option<PeerDeviceKeys> {
        self.peer_ratchet_keys
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(peer_node_id)
            .cloned()
    }

    /// Seal for a peer whose certificate the caller has verified. See [`seal`].
    pub fn seal_for(
        &self,
        peer: PeerRatchetKeys<'_>,
        app_payload: &[u8],
        now_unix: u64,
    ) -> Result<(Vec<u8>, [u8; ACK_KEY_LEN]), RatchetSpliceError> {
        let me = self.identity().ok_or(RatchetSpliceError::NoLocalInstance)?;
        seal(&self.store, &me, peer, app_payload, now_unix)
    }

    /// Open a payload from `sender_node_id`. See [`open`].
    pub fn open_payload(
        &self,
        sender_node_id: &[u8; 32],
        payload: &[u8],
        now_unix: u64,
    ) -> Result<Opened, RatchetSpliceError> {
        let me = self.identity().ok_or(RatchetSpliceError::NoLocalInstance)?;
        let devices = self.peer_devices(sender_node_id);
        open(
            &self.store,
            &me,
            sender_node_id,
            payload,
            devices.as_ref(),
            now_unix,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DK_SEED_BYTES, EK_BYTES, MLKEM_SEED_MIN_OVERLAP_SECS};

    const NOW: u64 = 1_800_000_000;

    /// One published device key, as the peer directory now holds them.
    ///
    /// A peer has one key PER DEVICE, and the cache keeps the set. These tests
    /// speak for one device each, so the set has one member.
    ///
    /// The instance is required rather than defaulted: the receive path asks
    /// for the pair, and a helper that invented an instance would make every
    /// test here pass against a directory that had forgotten which device
    /// published what.
    fn dev(instance_id: [u8; 16], pk: &[u8; 32]) -> PeerDeviceKeys {
        let mut d = PeerDeviceKeys::default();
        d.remember(instance_id, *pk, u64::MAX);
        d
    }

    struct Device {
        node_id: [u8; 32],
        instance_id: [u8; 16],
        ring: std::sync::Arc<MlKemSeedRing>,
        store: RatchetStore,
    }

    fn device(tag: u8) -> Device {
        let seed = [tag; DK_SEED_BYTES];
        let (ek, _) = crate::keypair_from_dk_seed(&seed).expect("keypair");
        Device {
            node_id: [tag; 32],
            instance_id: [tag; 16],
            ring: std::sync::Arc::new(MlKemSeedRing::new(0, seed, ek)),
            store: RatchetStore::new(),
        }
    }

    impl Device {
        fn me(&self) -> RatchetIdentity {
            RatchetIdentity {
                local_node_id: self.node_id,
                local_instance_id: self.instance_id,
                seed_ring: std::sync::Arc::clone(&self.ring),
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
            // The tests run around 0 and 1_000; far enough out that a
            // certificate's own end never decides a case that is about
            // something else, and every case that IS about it says so.
            authorized_until_unix: u64::MAX,
        }
    }

    /// Alice seals to Bob; Bob opens it. Returns Bob's result.
    fn a_to_b(a: &Device, b: &Device, msg: &[u8]) -> Result<Opened, RatchetSpliceError> {
        let (ek, pk) = (b.ek(), b.ratchet_pk());
        let payload = seal(&a.store, &a.me(), keys(b, &ek, &pk), msg, NOW)
            .expect("seal")
            .0;
        let a_pk = a.ratchet_pk();
        open(
            &b.store,
            &b.me(),
            &a.node_id,
            &payload,
            Some(&dev(a.instance_id, &a_pk)),
            NOW,
        )
    }

    /// A device that was legitimate stops being proven when its certificate
    /// stops saying so.
    ///
    /// The conversation still DECRYPTS — the keys are the keys, and revoking a
    /// device does not un-agree a root. What ends is the standing: the sender
    /// is no longer shown as proven, so it no longer bypasses the budget for
    /// unproven senders. A bit could not express that, and a bit is what was
    /// persisted (report17 V17-H1).
    #[test]
    fn a_proven_peer_stops_being_proven_when_its_certificate_does() {
        let a = device(1);
        let b = device(2);
        let expires = NOW + 100;

        // A seals to B out of a certificate good until `expires`.
        let (ek, pk) = (b.ek(), b.ratchet_pk());
        let payload = seal(
            &a.store,
            &a.me(),
            PeerRatchetKeys {
                node_id: &b.node_id,
                instance_id: &b.instance_id,
                mlkem_ek: &ek,
                ratchet_pk: &pk,
                authorized_until_unix: expires,
            },
            b"hello",
            NOW,
        )
        .expect("seal")
        .0;
        let a_pk = a.ratchet_pk();
        open(
            &b.store,
            &b.me(),
            &a.node_id,
            &payload,
            Some(&dev(a.instance_id, &a_pk)),
            NOW,
        )
        .expect("B opens");

        // B answers twice: once inside the certificate's window, once after.
        let reply = |at: u64| {
            let (ek, pk) = (a.ek(), a.ratchet_pk());
            seal(
                &b.store,
                &b.me(),
                PeerRatchetKeys {
                    node_id: &a.node_id,
                    instance_id: &a.instance_id,
                    mlkem_ek: &ek,
                    ratchet_pk: &pk,
                    authorized_until_unix: u64::MAX,
                },
                b"and back",
                at,
            )
            .expect("seal")
            .0
        };
        let inside = reply(NOW);
        let outside = reply(NOW + 1);

        // Inside: proven, as it always was.
        let opened =
            open(&a.store, &a.me(), &b.node_id, &inside, None, expires - 1).expect("A opens");
        assert!(
            opened.authenticated,
            "premise: a live certificate proves the peer"
        );

        // Outside: the same session, the same keys — it opens, and it is no
        // longer proven.
        let opened = open(&a.store, &a.me(), &b.node_id, &outside, None, expires + 1)
            .expect("the conversation still decrypts after the certificate lapses");
        assert!(
            !opened.authenticated,
            "a device kept its proven standing after its certificate expired"
        );
    }

    /// And it survives a restart the same way, because the stamp is what is
    /// written down.
    #[test]
    fn the_authorization_stamp_is_persisted_and_a_bare_bit_is_not_believed() {
        // A real conversation, so the session inside the blob is a real one.
        let a = device(3);
        let b = device(4);
        let (ek, pk) = (b.ek(), b.ratchet_pk());
        seal(&a.store, &a.me(), keys(&b, &ek, &pk), b"x", NOW).expect("seal");
        let blob = {
            let mut g = a.store.lock();
            let entry = g.entries.values_mut().next().expect("entry");
            entry.authenticated_until = NOW + 500;
            entry.encode()
        };
        let back = Entry::decode(&blob).expect("decode");
        assert_eq!(
            back.authenticated_until,
            NOW + 500,
            "the stamp did not survive being written down"
        );
        assert!(back.is_authenticated(NOW));
        assert!(
            !back.is_authenticated(NOW + 501),
            "a restored conversation is proven forever again"
        );

        // A blob from a build that had only the bit: everything up to the
        // stamp, and the byte still says "yes, once".
        let older = &blob[..blob.len() - 8];
        assert_eq!(older[4 + 1 + 32], 1, "premise: the bit says proven");
        let restored = Entry::decode(older).expect("an older blob still loads");
        assert_eq!(
            restored.authenticated_until, 0,
            "a bit with no expiry was restored as proof, which is what \
             outlived every revocation"
        );
        assert!(
            !restored.is_authenticated(NOW),
            "the peer is shown as proven on the strength of a bit"
        );
    }

    /// A bare bit is not proof of standing, and it is still proof of history.
    ///
    /// The migration answered the first question and, by answering it with the
    /// same field, answered the second one too: `ever_proven` was derived from
    /// the stamp, so a conversation restored from an older blob came back
    /// droppable. That is exactly what the doc on `ever_proven` forbids — a
    /// conversation whose evidence has merely gone stale must not become a
    /// slot an inbound prologue may take — and an upgrade is the one moment
    /// when every conversation on the device is in that state at once
    /// (report18 V18-H1).
    #[test]
    fn a_legacy_bit_costs_standing_and_not_the_conversation() {
        let a = device(5);
        let b = device(6);
        let (ek, pk) = (b.ek(), b.ratchet_pk());
        seal(&a.store, &a.me(), keys(&b, &ek, &pk), b"x", NOW).expect("seal");
        let blob = {
            let mut g = a.store.lock();
            let entry = g.entries.values_mut().next().expect("entry");
            entry.authenticated_until = NOW + 500;
            entry.encode()
        };

        let older = &blob[..blob.len() - 8];
        assert_eq!(older[4 + 1 + 32], 1, "premise: the bit says proven");
        let restored = Entry::decode(older).expect("an older blob still loads");

        assert_eq!(
            restored.authenticated_until, 0,
            "a bit with no expiry was restored as standing"
        );
        assert!(!restored.is_authenticated(NOW), "shown as proven on a bit");
        assert!(
            restored.ever_proven(),
            "an upgrade forgot that this conversation was ever vouched for"
        );
        assert!(
            !restored.droppable(),
            "an upgrade made a proven conversation a slot a stranger may take"
        );

        // And it survives being written down again, or the next save undoes
        // the migration.
        let again = Entry::decode(&restored.encode()).expect("round trip");
        assert!(again.ever_proven(), "re-encoding dropped the history");
        assert!(
            !again.is_authenticated(NOW),
            "re-encoding invented standing"
        );
    }

    /// One peer, two devices, and both of them are that peer.
    ///
    /// A certificate is per DEVICE, so a peer with a phone and a laptop
    /// publishes two device keys. The directory held ONE key per node, so
    /// whichever sibling's certificate resolved last overwrote the other — and
    /// an authentic prologue from the overwritten device then failed the
    /// comparison and was filed as merely claimed (report14 V14-M6). The
    /// message still opened; what it lost was its name, and with it the right
    /// to take back a conversation a stranger opened first.
    #[test]
    fn either_device_of_one_peer_authenticates() {
        fn peer_device(node: u8, instance: u8, seed_tag: u8) -> Device {
            let seed = [seed_tag; DK_SEED_BYTES];
            let (ek, _) = crate::keypair_from_dk_seed(&seed).expect("keypair");
            Device {
                node_id: [node; 32],
                instance_id: [instance; 16],
                ring: std::sync::Arc::new(MlKemSeedRing::new(0, seed, ek)),
                store: RatchetStore::new(),
            }
        }

        let me = device(9);
        // ONE identity: same node id, two of its devices.
        let phone = peer_device(5, 0xA1, 0x11);
        let laptop = peer_device(5, 0xB2, 0x22);
        assert_eq!(phone.node_id, laptop.node_id);
        assert_ne!(
            phone.ratchet_pk(),
            laptop.ratchet_pk(),
            "two devices of one identity publish two device keys — if they \
             published one, this test is about nothing"
        );

        // What the directory holds after both certificates have been resolved.
        let mut published = PeerDeviceKeys::default();
        published.remember(phone.instance_id, phone.ratchet_pk(), u64::MAX);
        published.remember(laptop.instance_id, laptop.ratchet_pk(), u64::MAX);
        assert_eq!(published.len(), 2, "one slot per node is the defect");

        let seal_to_me = |from: &Device, body: &[u8]| {
            let (ek, pk) = (me.ek(), me.ratchet_pk());
            seal(&from.store, &from.me(), keys(&me, &ek, &pk), body, NOW)
                .expect("seal")
                .0
        };

        for (who, body) in [
            (&phone, &b"from the phone"[..]),
            (&laptop, &b"from the laptop"[..]),
        ] {
            let payload = seal_to_me(who, body);
            let opened = open(
                &me.store,
                &me.me(),
                &who.node_id,
                &payload,
                Some(&published),
                NOW,
            )
            .expect("open");
            assert_eq!(opened.plaintext, body);
            assert!(
                opened.authenticated,
                "this device's key IS one the identity published; calling it \
                 unproven is the multi-device delivery defect"
            );
        }

        // The vacuity guard: a key the peer never published still fails. The
        // set widens what counts as the peer, it does not stop counting.
        let stranger = peer_device(7, 0xC3, 0x33);
        let payload = seal_to_me(&stranger, b"not this identity");
        let opened = open(
            &me.store,
            &me.me(),
            &stranger.node_id,
            &payload,
            Some(&published),
            NOW,
        )
        .expect("open");
        assert!(
            !opened.authenticated,
            "a key nobody published must not authenticate anyone"
        );
    }

    /// The directory keeps a bounded number of keys per peer, newest first.
    #[test]
    fn the_device_directory_is_bounded_and_newest_first() {
        let mut d = PeerDeviceKeys::default();
        for i in 0..(PeerDeviceKeys::MAX as u8 + 3) {
            d.remember([i; 16], [i; 32], u64::MAX);
        }
        assert_eq!(
            d.len(),
            PeerDeviceKeys::MAX,
            "one peer may not grow forever"
        );
        assert_eq!(
            d.newest(),
            Some([PeerDeviceKeys::MAX as u8 + 2; 32]),
            "the key that arrived last is the one a caller wanting ONE gets"
        );
        assert!(
            !d.contains(&[0u8; 16], &[0u8; 32], NOW),
            "the oldest fell out, which is what bounded means"
        );

        // Re-publishing a key it already holds moves it, and adds nothing.
        let held = d.len();
        let existing = d.newest().expect("something");
        let existing_instance = [PeerDeviceKeys::MAX as u8 + 2; 16];
        d.remember(existing_instance, existing, u64::MAX);
        assert_eq!(d.len(), held);
        assert_eq!(d.newest(), Some(existing));
    }

    /// report12 X-H5: the position is what a host records BEFORE it publishes,
    /// and the skip is what a restart applies. This pins the store's half of
    /// that — the cryptographic property is pinned in `veil-ratchet` itself.
    #[test]
    fn a_skip_that_moves_the_chain_marks_the_conversation_dirty() {
        let (a, b) = (device(1), device(2));
        a_to_b(&a, &b, b"first").expect("open");
        let key = a.store.keys().first().copied().expect("a conversation");

        let at = a.store.send_position(&key).expect("a sending chain");
        let _ = a.store.drain_dirty();

        // A position we have already passed changes nothing, and a store that
        // marked it dirty anyway would have the host writing for no reason.
        assert_eq!(a.store.skip_send_to(&key, at).expect("skip"), 0);
        assert!(
            a.store.drain_dirty().is_empty(),
            "nothing moved, so nothing is owed to disk"
        );

        let ahead = veil_ratchet::SendPosition {
            next: at.next + 3,
            ..at
        };
        assert_eq!(a.store.skip_send_to(&key, ahead).expect("skip"), 3);
        assert_eq!(
            a.store.send_position(&key).expect("still held").next,
            at.next + 3
        );
        assert_eq!(
            a.store.drain_dirty(),
            vec![key],
            "the chain moved, so the state on disk is behind and must be written"
        );
    }

    #[test]
    fn a_position_for_a_conversation_we_do_not_hold_is_not_an_answer() {
        let a = device(1);
        let missing = ConversationKey::from_storage_key(&[9u8; CONVERSATION_KEY_LEN]);
        assert!(a.store.send_position(&missing).is_none());
        assert_eq!(
            a.store.skip_send_to(
                &missing,
                veil_ratchet::SendPosition {
                    chain: [0u8; 32],
                    next: 5
                }
            ),
            Err(RatchetSkipError::NoConversation)
        );
    }

    /// report12 V-M10: eviction only ever takes an UNPROVEN conversation, so a
    /// flood could never cost anyone a proven one. What it could do is take
    /// every unproven slot in turn — one sender, varying its instance id —
    /// and every eviction costs the host a blob delete and the scrub after it.
    ///
    /// A peer now churns its OWN quota instead of the store's.
    /// report12 V-M10: `MAX_SKIP_TOTAL` bounds ONE conversation and
    /// `MAX_CONVERSATIONS` bounds the count, but their product is two million
    /// banked 32-byte secrets — hundreds of megabytes, all of it put there by
    /// somebody else's frames.
    ///
    /// The sum is bounded now, and the sweep takes only from conversations
    /// this device has never spoken on: a quota that could make a real
    /// correspondent's messages unreadable would be a worse bug than the one
    /// it fixes.
    #[test]
    fn the_sweep_takes_from_a_stranger_and_spares_one_we_answered() {
        let (a, b) = (device(1), device(2));

        // A real banked key: b sends two, a opens only the second, so the
        // first's key is banked against its late arrival.
        let (ek, pk) = (a.ek(), a.ratchet_pk());
        let first = seal(&b.store, &b.me(), keys(&a, &ek, &pk), b"one", NOW)
            .expect("seal")
            .0;
        let second = seal(&b.store, &b.me(), keys(&a, &ek, &pk), b"two", NOW)
            .expect("seal")
            .0;
        let b_pk = b.ratchet_pk();
        open(
            &a.store,
            &a.me(),
            &b.node_id,
            &second,
            Some(&dev(b.instance_id, &b_pk)),
            NOW,
        )
        .expect("open");
        let key = a.store.keys().first().copied().expect("a conversation");
        assert!(
            a.store.lock().entries[&key].session.skipped_len() > 0,
            "the fixture banked nothing, so the sweep below is not tested"
        );

        // Answered, so it is proven — and a budget of zero would sweep
        // anything sweepable.
        {
            let mut g = a.store.lock();
            g.entries.get_mut(&key).unwrap().authenticated_until = u64::MAX;
            assert_eq!(
                g.enforce_skipped_budget_to(0),
                0,
                "a conversation this device has spoken on keeps its bank, \
                 whatever the pressure"
            );
            assert!(g.entries[&key].session.skipped_len() > 0);

            // The same conversation unproven is exactly what a flood produces.
            g.entries.get_mut(&key).unwrap().authenticated_until = 0;
            let freed = g.enforce_skipped_budget_to(0);
            assert!(
                freed > 0,
                "an unproven bank over budget must be swept: it is the class a \
                 stranger can fill"
            );
        }

        // And the ordinary case costs nothing: under budget, nothing moves.
        assert_eq!(a.store.lock().enforce_skipped_budget(), 0);
        drop(first);
    }

    #[test]
    fn one_peer_cannot_churn_more_than_its_own_share() {
        // `a` receives; the flood comes from node 2; `other` is a genuinely
        // different node — an earlier version reused node 2 here and then
        // asked why "another peer" was being refused.
        let (a, other) = (device(1), device(3));

        // Twice the quota of conversations from the SAME peer, each from a
        // different device instance — the shape of the flood.
        //
        // Opened WITHOUT the sender's ratchet key, which is what makes them
        // unproven: a stranger cannot make us answer, and an answered
        // conversation is authenticated and outside this quota entirely. An
        // earlier version of this test handed the key over and then wondered
        // why the cap did nothing.
        let mut spoken = 0;
        for i in 0..(MAX_UNPROVEN_PER_PEER as u8 * 2) {
            let mut sender = device(2);
            sender.instance_id = [i.wrapping_add(1); 16];
            let (ek, pk) = (a.ek(), a.ratchet_pk());
            let payload = seal(
                &sender.store,
                &sender.me(),
                keys(&a, &ek, &pk),
                b"hello",
                NOW,
            )
            .expect("seal")
            .0;
            if open(&a.store, &a.me(), &sender.node_id, &payload, None, NOW).is_ok() {
                spoken += 1;
            }
        }
        assert!(
            spoken > MAX_UNPROVEN_PER_PEER,
            "the fixture must actually get past the quota, or nothing is tested"
        );
        assert_eq!(
            a.store.len(),
            MAX_UNPROVEN_PER_PEER,
            "one peer must not hold more unproven conversations than its share"
        );

        // And a DIFFERENT peer still gets in: the quota is per sender, not a
        // shared ceiling the first arrival can spend on everyone's behalf.
        a_to_b(&other, &a, b"from somebody else").expect("open");
        assert_eq!(
            a.store.len(),
            MAX_UNPROVEN_PER_PEER + 1,
            "another peer's first conversation must still be admitted"
        );
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

    /// Alice and Bob, established and answered, so Alice's frames are bare
    /// from here — the prologue is only re-attached until the peer replies.
    fn settled_pair(tag: u8) -> (Device, Device) {
        let (a, b) = (device(tag), device(tag ^ 0xff));
        a_to_b(&a, &b, b"one").expect("first contact");
        let (aek, apk) = (a.ek(), a.ratchet_pk());
        let back = seal(&b.store, &b.me(), keys(&a, &aek, &apk), b"ack", NOW)
            .expect("seal")
            .0;
        let b_pk = b.ratchet_pk();
        open(
            &a.store,
            &a.me(),
            &b.node_id,
            &back,
            Some(&dev(b.instance_id, &b_pk)),
            NOW,
        )
        .expect("Alice opens");
        (a, b)
    }

    /// One of Alice's bare frames, damaged: whatever the real cause — a
    /// restored backup, a re-keyed device, a wire format that moved — what Bob
    /// sees is a frame of hers that will not open.
    fn unopenable_frame_from(a: &Device, b: &Device) -> Vec<u8> {
        let (bek, bpk) = (b.ek(), b.ratchet_pk());
        let mut f = seal(&a.store, &a.me(), keys(b, &bek, &bpk), b"x", NOW)
            .expect("seal")
            .0;
        *f.last_mut().expect("non-empty") ^= 1;
        f
    }

    #[test]
    fn a_conversation_that_stops_opening_frames_is_given_up() {
        // A proven conversation is otherwise permanent, and that is a trap once
        // it stops working: it refuses every prologue that would replace it,
        // and the peer is never told its frames are unreadable. Measured on two
        // devices as 48 refusals in a row with no way back.
        let (a, b) = settled_pair(0xC9);
        let a_pk = a.ratchet_pk();

        // Asserted with a LITERAL, not with the constant: a loop written as
        // `1..WEDGED_AFTER_FRAME_FAILURES` empties itself the moment the
        // constant becomes 1, and a test that adapts to the number it is
        // guarding cannot catch that number being wrong. One lost frame must
        // never cost the conversation, whatever the threshold is set to.
        //
        // In a `const` block so it is the BUILD that fails, not this test: a
        // threshold of 1 is wrong for every caller, not just for this case.
        const {
            assert!(
                WEDGED_AFTER_FRAME_FAILURES >= 2,
                "one bad frame has to be forgiven"
            )
        };
        let f = unopenable_frame_from(&a, &b);
        assert!(matches!(
            open(
                &b.store,
                &b.me(),
                &a.node_id,
                &f,
                Some(&dev(a.instance_id, &a_pk)),
                NOW
            ),
            Err(RatchetSpliceError::Ratchet(_))
        ));
        assert_eq!(
            b.store.len(),
            1,
            "one frame that would not open is not evidence of a wedge"
        );

        for attempt in 2..WEDGED_AFTER_FRAME_FAILURES {
            let f = unopenable_frame_from(&a, &b);
            assert!(
                matches!(
                    open(
                        &b.store,
                        &b.me(),
                        &a.node_id,
                        &f,
                        Some(&dev(a.instance_id, &a_pk)),
                        NOW
                    ),
                    Err(RatchetSpliceError::Ratchet(_))
                ),
                "attempt {attempt} is still short of the threshold"
            );
            assert_eq!(b.store.len(), 1, "the conversation is still held");
        }

        let f = unopenable_frame_from(&a, &b);
        assert!(matches!(
            open(
                &b.store,
                &b.me(),
                &a.node_id,
                &f,
                Some(&dev(a.instance_id, &a_pk)),
                NOW
            ),
            Err(RatchetSpliceError::WedgedConversationDropped)
        ));
        assert_eq!(
            b.store.len(),
            0,
            "a conversation that cannot open the peer's frames is not kept"
        );
    }

    #[test]
    fn a_frame_that_opens_forgives_the_streak() {
        // The failures have to be CONSECUTIVE, or a conversation that loses one
        // frame a week would eventually be given up for no reason.
        let (a, b) = settled_pair(0xCA);
        let a_pk = a.ratchet_pk();
        for _ in 1..WEDGED_AFTER_FRAME_FAILURES {
            let f = unopenable_frame_from(&a, &b);
            let _ = open(
                &b.store,
                &b.me(),
                &a.node_id,
                &f,
                Some(&dev(a.instance_id, &a_pk)),
                NOW,
            );
        }
        a_to_b(&a, &b, b"still here").expect("a good frame opens");
        // Streak cleared: the same number of failures again must not be enough.
        for _ in 1..WEDGED_AFTER_FRAME_FAILURES {
            let f = unopenable_frame_from(&a, &b);
            let _ = open(
                &b.store,
                &b.me(),
                &a.node_id,
                &f,
                Some(&dev(a.instance_id, &a_pk)),
                NOW,
            );
        }
        assert_eq!(b.store.len(), 1, "the conversation survived");
    }

    #[test]
    fn a_replayed_prologue_never_counts_toward_the_wedge() {
        // The reason only BARE frames count. A prologue that fails is how a
        // peer legitimately starts over, and an old one can be replayed by
        // anyone who saw it — counting those would hand a recorded prologue the
        // power to unseat a live conversation by first wedging it.
        let (a, b) = (device(0xCB), device(0xDB));
        let (bek, bpk) = (b.ek(), b.ratchet_pk());
        let prologue = seal(&a.store, &a.me(), keys(&b, &bek, &bpk), b"race", NOW)
            .expect("seal")
            .0;
        let a_pk = a.ratchet_pk();
        open(
            &b.store,
            &b.me(),
            &a.node_id,
            &prologue,
            Some(&dev(a.instance_id, &a_pk)),
            NOW,
        )
        .expect("first open");

        // Walk the conversation on, so the recorded prologue is genuinely
        // BEHIND the session and replaying it FAILS. Replaying one the session
        // can still open proves nothing — it never reaches the counter at all,
        // which is how the first version of this test passed while testing
        // nothing.
        for i in 0..4u8 {
            a_to_b(&a, &b, &[i; 5]).expect("conversation continues");
        }
        let mut refused = 0;
        // The CHANGE count, not the final size: dropping the conversation and
        // then letting the next replay start a fresh one leaves the size back
        // at one, so a size check reads as "nothing happened" when in fact the
        // live conversation was thrown away and replaced.
        let version_before = b.store.version();
        for _ in 0..(WEDGED_AFTER_FRAME_FAILURES * 3) {
            if open(
                &b.store,
                &b.me(),
                &a.node_id,
                &prologue,
                Some(&dev(a.instance_id, &a_pk)),
                NOW,
            )
            .is_err()
            {
                refused += 1;
            }
        }
        assert!(
            refused >= WEDGED_AFTER_FRAME_FAILURES,
            "the replays have to actually fail for this test to mean anything \
             (refused {refused})"
        );
        assert_eq!(
            b.store.version(),
            version_before,
            "a replayed prologue moved the conversation"
        );
        assert_eq!(
            b.store.len(),
            1,
            "replaying a prologue must not be able to drop the conversation"
        );
    }

    #[test]
    fn a_conversation_flows_both_ways() {
        let (a, b) = (device(0xA2), device(0xB2));
        a_to_b(&a, &b, b"one").expect("open");
        for i in 0..4u8 {
            let (ek, pk) = (a.ek(), a.ratchet_pk());
            let back = seal(&b.store, &b.me(), keys(&a, &ek, &pk), &[i; 9], NOW)
                .expect("seal")
                .0;
            let b_pk = b.ratchet_pk();
            let got = open(
                &a.store,
                &a.me(),
                &b.node_id,
                &back,
                Some(&dev(b.instance_id, &b_pk)),
                NOW,
            )
            .expect("open");
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
        let first = seal(&a.store, &a.me(), keys(&b, &ek, &pk), b"1", NOW)
            .expect("seal")
            .0;
        assert_eq!(first[2], KIND_PROLOGUE);

        // Still no answer from Bob, so the prologue is repeated — a lost first
        // transmission must not strand the conversation.
        let second = seal(&a.store, &a.me(), keys(&b, &ek, &pk), b"2", NOW)
            .expect("seal")
            .0;
        assert_eq!(second[2], KIND_PROLOGUE);
        assert_eq!(
            &second[HEADER_LEN..HEADER_LEN + PQXDH_PROLOGUE_LEN],
            &first[HEADER_LEN..HEADER_LEN + PQXDH_PROLOGUE_LEN],
            "a repeat must re-send the SAME prologue; a second key agreement \
             would derive an unrelated root and orphan the first"
        );

        // Bob answers. Now Alice knows he has it.
        let a_pk = a.ratchet_pk();
        open(
            &b.store,
            &b.me(),
            &a.node_id,
            &second,
            Some(&dev(a.instance_id, &a_pk)),
            NOW,
        )
        .expect("open");
        let (aek, apk) = (a.ek(), a.ratchet_pk());
        let reply = seal(&b.store, &b.me(), keys(&a, &aek, &apk), b"got it", NOW)
            .expect("seal")
            .0;
        let b_pk = b.ratchet_pk();
        open(
            &a.store,
            &a.me(),
            &b.node_id,
            &reply,
            Some(&dev(b.instance_id, &b_pk)),
            NOW,
        )
        .expect("open");

        let third = seal(&a.store, &a.me(), keys(&b, &ek, &pk), b"3", NOW)
            .expect("seal")
            .0;
        assert_eq!(third[2], KIND_FRAME, "the prologue must stop once answered");
    }

    #[test]
    fn a_lost_first_message_is_recovered_by_the_repeated_prologue() {
        let (a, b) = (device(0xA4), device(0xB4));
        let (ek, pk) = (b.ek(), b.ratchet_pk());
        let lost = seal(&a.store, &a.me(), keys(&b, &ek, &pk), b"lost", NOW)
            .expect("seal")
            .0;
        let kept = seal(&a.store, &a.me(), keys(&b, &ek, &pk), b"kept", NOW)
            .expect("seal")
            .0;
        drop(lost);
        let a_pk = a.ratchet_pk();
        let got = open(
            &b.store,
            &b.me(),
            &a.node_id,
            &kept,
            Some(&dev(a.instance_id, &a_pk)),
            NOW,
        )
        .expect("open");
        assert_eq!(got.plaintext, b"kept");
    }

    #[test]
    fn an_unknown_sender_key_opens_but_is_not_authenticated() {
        let (a, b) = (device(0xA5), device(0xB5));
        let (ek, pk) = (b.ek(), b.ratchet_pk());
        let payload = seal(&a.store, &a.me(), keys(&b, &ek, &pk), b"who am i", NOW)
            .expect("seal")
            .0;
        // Bob has not resolved Alice's certificate yet.
        let got = open(&b.store, &b.me(), &a.node_id, &payload, None, NOW).expect("open");
        assert_eq!(got.plaintext, b"who am i");
        assert!(
            !got.authenticated,
            "an unmatched device key is a claim, and must be reported as one"
        );

        // It settles the moment the certificate is in hand.
        let next = seal(&a.store, &a.me(), keys(&b, &ek, &pk), b"still me", NOW)
            .expect("seal")
            .0;
        let a_pk = a.ratchet_pk();
        let got = open(
            &b.store,
            &b.me(),
            &a.node_id,
            &next,
            Some(&dev(a.instance_id, &a_pk)),
            NOW,
        )
        .expect("open");
        assert!(got.authenticated);
    }

    /// report16 V16-H1: a certificate stops saying it, and the cache did not
    /// notice.
    ///
    /// Validity is checked once, when the certificate is resolved. This cache
    /// is what the receive path consults afterwards, and it kept the key with
    /// no expiry at all — so a device whose certificate ran out went on
    /// authenticating new conversations for as long as the process lived. The
    /// authenticated bit is persisted, so it outlived that too.
    ///
    /// Authenticated is not a label: it is what makes a conversation
    /// untouchable by eviction and what marks a delivery as coming from a
    /// device this identity vouches for. Neither should survive the vouching.
    #[test]
    fn a_key_whose_certificate_expired_no_longer_authenticates() {
        let (a, b) = (device(0xA8), device(0xB8));
        let a_pk = a.ratchet_pk();
        let expires = NOW + 3600;

        // While the certificate still says so.
        let (ek, pk) = (b.ek(), b.ratchet_pk());
        let payload = seal(&a.store, &a.me(), keys(&b, &ek, &pk), b"hello", NOW)
            .expect("seal")
            .0;
        let mut published = PeerDeviceKeys::default();
        published.remember(a.instance_id, a_pk, expires);
        let live = open(
            &b.store,
            &b.me(),
            &a.node_id,
            &payload,
            Some(&published),
            NOW,
        )
        .expect("open");
        assert!(
            live.authenticated,
            "a live certificate must still authenticate, or this test is \
             about nothing"
        );

        // The same key, the same device, one second past the certificate.
        let (c, d) = (device(0xC8), device(0xD8));
        let c_pk = c.ratchet_pk();
        let (ek2, pk2) = (d.ek(), d.ratchet_pk());
        let later = seal(&c.store, &c.me(), keys(&d, &ek2, &pk2), b"hello", NOW)
            .expect("seal")
            .0;
        let mut stale = PeerDeviceKeys::default();
        stale.remember(c.instance_id, c_pk, expires);
        let got = open(
            &d.store,
            &d.me(),
            &c.node_id,
            &later,
            Some(&stale),
            expires + 1,
        )
        .expect("open");

        assert!(
            !got.authenticated,
            "a certificate that has run out still vouched for its device"
        );
    }

    /// report15 V15-M5: a certificate names a DEVICE and a key. Keeping only
    /// the key turns one verified device into an unlimited supply of
    /// authenticated conversations.
    ///
    /// Authenticated is not a label: it is what makes a conversation
    /// untouchable by eviction, so a contact whose key was verified once could
    /// take every slot in the store by renaming itself, and honest peers get
    /// StoreFull.
    #[test]
    fn a_verified_key_under_a_made_up_instance_is_not_authenticated() {
        let (a, b) = (device(0xA7), device(0xB7));
        let a_pk = a.ratchet_pk();

        // The real device: key and instance both from the certificate.
        let honest = a_to_b(&a, &b, b"hello").expect("open");
        assert!(
            honest.authenticated,
            "the genuine device must still authenticate, or this test is \
             about nothing"
        );

        // The same identity, the same verified key, a different instance in
        // the header. Nothing about the certificate says this device exists.
        let mut renamed = device(0xA7);
        renamed.instance_id = [0x5e; 16];
        renamed.ring = a.ring.clone();
        let (ek, pk) = (b.ek(), b.ratchet_pk());
        let payload = seal(
            &renamed.store,
            &renamed.me(),
            keys(&b, &ek, &pk),
            b"hi",
            NOW,
        )
        .expect("seal")
        .0;
        let got = open(
            &b.store,
            &b.me(),
            &a.node_id,
            &payload,
            // The directory as it stands: one certificate, for the REAL device.
            Some(&dev(a.instance_id, &a_pk)),
            NOW,
        )
        .expect("open");

        assert!(
            !got.authenticated,
            "a made-up instance was authenticated on another device's key"
        );
    }

    #[test]
    fn a_sender_announcing_the_wrong_key_is_not_authenticated() {
        let (a, b) = (device(0xA6), device(0xB6));
        let (ek, pk) = (b.ek(), b.ratchet_pk());
        let payload = seal(&a.store, &a.me(), keys(&b, &ek, &pk), b"impostor", NOW)
            .expect("seal")
            .0;
        // Anyone can seal to Bob's published key and name any sender. Handing
        // Bob a DIFFERENT certificate for that name must not authenticate it.
        let someone_else = device(0xC6).ratchet_pk();
        let got = open(
            &b.store,
            &b.me(),
            &a.node_id,
            &payload,
            Some(&dev(a.instance_id, &someone_else)),
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
        let forged = seal(
            &impostor.store,
            &impostor.me(),
            keys(&b, &ek, &pk),
            b"reset",
            NOW,
        )
        .expect("seal")
        .0;
        let a_pk = a.ratchet_pk();
        assert!(
            open(
                &b.store,
                &b.me(),
                &a.node_id,
                &forged,
                Some(&dev(a.instance_id, &a_pk)),
                NOW
            )
            .is_err(),
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
            NOW,
        )
        .expect("seal")
        .0;
        let a_pk = a.ratchet_pk();
        let got = open(
            &b.store,
            &b.me(),
            &a.node_id,
            &grab,
            Some(&dev(a.instance_id, &a_pk)),
            NOW,
        )
        .expect("open");
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
            NOW,
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
                Some(&dev(b.instance_id, &b_pk)),
                NOW
            )
            .is_err(),
            "the squatter read a message Bob wrote to Alice"
        );
        assert_eq!(
            open(
                &a.store,
                &a.me(),
                &b.node_id,
                &out,
                Some(&dev(b.instance_id, &b_pk)),
                NOW
            )
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
            NOW,
        )
        .expect("seal")
        .0;
        let a_pk = a.ratchet_pk();
        open(
            &b.store,
            &b.me(),
            &a.node_id,
            &grab,
            Some(&dev(a.instance_id, &a_pk)),
            NOW,
        )
        .expect("open");

        let real = a_to_b(&a, &b, b"it is actually me").expect("the real contact was locked out");
        assert_eq!(real.plaintext, b"it is actually me");
        assert!(real.authenticated);

        // And the squatter's session went with it.
        let more = seal(
            &squatter.store,
            &squatter.me(),
            keys(&b, &bek, &bpk),
            b"still here",
            NOW,
        )
        .expect("seal")
        .0;
        assert!(
            open(
                &b.store,
                &b.me(),
                &a.node_id,
                &more,
                Some(&dev(a.instance_id, &a_pk)),
                NOW
            )
            .is_err(),
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
        let payload = seal(&a.store, &a.me(), keys(&b, &bek, &bpk), b"race", NOW)
            .expect("seal")
            .0;
        let a_pk = a.ratchet_pk();

        let results: Vec<_> = std::thread::scope(|s| {
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    s.spawn(|| {
                        open(
                            &b.store,
                            &b.me(),
                            &a.node_id,
                            &payload,
                            Some(&dev(a.instance_id, &a_pk)),
                            NOW,
                        )
                    })
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
        let opening = seal(&a.store, &a.me(), keys(&b, &bek, &bpk), b"hello", NOW)
            .expect("seal")
            .0;
        let a_pk = a.ratchet_pk();
        open(
            &b.store,
            &b.me(),
            &a.node_id,
            &opening,
            Some(&dev(a.instance_id, &a_pk)),
            NOW,
        )
        .expect("open");

        let key = b.store.keys()[0];
        let before_blob = b.store.export(&key).expect("held");
        let before_version = b.store.version();

        assert!(
            open(
                &b.store,
                &b.me(),
                &a.node_id,
                &opening,
                Some(&dev(a.instance_id, &a_pk)),
                NOW
            )
            .is_err(),
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
        let first = seal(&a.store, &a.me(), keys(&b, &bek, &bpk), b"hello", NOW)
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
            NOW,
        )
        .expect("seal")
        .0;
        let a_pk = a.ratchet_pk();
        assert!(
            open(
                &b.store,
                &b.me(),
                &a.node_id,
                &forged,
                Some(&dev(a.instance_id, &a_pk)),
                NOW
            )
            .is_err(),
            "a stranger displaced a conversation it cannot prove is its own"
        );

        // Alice's conversation is untouched, and settles the moment she speaks
        // again against the certificate Bob now holds.
        let next = seal(&a.store, &a.me(), keys(&b, &bek, &bpk), b"still me", NOW)
            .expect("seal")
            .0;
        let got = open(
            &b.store,
            &b.me(),
            &a.node_id,
            &next,
            Some(&dev(a.instance_id, &a_pk)),
            NOW,
        )
        .expect("open");
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
        let reply = seal(
            &b.store,
            &b.me(),
            keys(&a, &aek, &apk),
            b"still talking",
            NOW,
        )
        .expect("seal")
        .0;
        assert_eq!(
            reply[2], KIND_FRAME,
            "a rotation must not replace the conversation"
        );
        let b_pk = b.ratchet_pk();
        assert_eq!(
            open(
                &a.store,
                &a.me(),
                &b.node_id,
                &reply,
                Some(&dev(b.instance_id, &b_pk)),
                NOW
            )
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
        seal(
            &a.store,
            &a.me(),
            keys(&b, &bek, &bpk),
            b"anyone there",
            NOW,
        )
        .expect("seal");

        let (aek, apk) = (a.ek(), a.ratchet_pk());
        let fresh = seal(
            &b.store,
            &b.me(),
            keys(&a, &aek, &apk),
            b"starting over",
            NOW,
        )
        .expect("seal")
        .0;
        let b_pk = b.ratchet_pk();
        let got = open(
            &a.store,
            &a.me(),
            &b.node_id,
            &fresh,
            Some(&dev(b.instance_id, &b_pk)),
            NOW,
        )
        .expect("open");
        assert_eq!(got.plaintext, b"starting over");
        assert!(got.authenticated);

        // And the conversation now runs on the session the peer opened.
        let back = seal(&a.store, &a.me(), keys(&b, &bek, &bpk), b"here now", NOW)
            .expect("seal")
            .0;
        assert_eq!(back[2], KIND_FRAME);
        let a_pk = a.ratchet_pk();
        assert_eq!(
            open(
                &b.store,
                &b.me(),
                &a.node_id,
                &back,
                Some(&dev(a.instance_id, &a_pk)),
                NOW
            )
            .expect("open")
            .plaintext,
            b"here now"
        );
    }

    #[test]
    fn a_payload_for_another_device_is_refused_before_any_key_work() {
        let (a, b) = (device(0xA8), device(0xB8));
        let (ek, pk) = (b.ek(), b.ratchet_pk());
        let payload = seal(&a.store, &a.me(), keys(&b, &ek, &pk), b"x", NOW)
            .expect("seal")
            .0;
        let other = device(0xD8);
        let me = RatchetIdentity {
            local_node_id: b.node_id,
            local_instance_id: other.instance_id,
            seed_ring: std::sync::Arc::clone(&b.ring),
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
        let good = seal(&a.store, &a.me(), keys(&b, &ek, &pk), b"downgrade me", NOW)
            .expect("seal")
            .0;
        assert_eq!(good[2], KIND_PROLOGUE);

        let a_pk = a.ratchet_pk();
        assert_eq!(
            open(
                &b.store,
                &b.me(),
                &a.node_id,
                &strip_the_post_quantum_leg(&good),
                Some(&dev(a.instance_id, &a_pk)),
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
            open(
                &b.store,
                &b.me(),
                &a.node_id,
                &good,
                Some(&dev(a.instance_id, &a_pk)),
                NOW
            )
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
        let good = seal(&a.store, &a.me(), keys(&b, &ek, &pk), b"downgrade me", NOW)
            .expect("seal")
            .0;
        let key = b.store.keys()[0];
        let before = b.store.export(&key).expect("held");

        let a_pk = a.ratchet_pk();
        assert_eq!(
            open(
                &b.store,
                &b.me(),
                &a.node_id,
                &strip_the_post_quantum_leg(&good),
                Some(&dev(a.instance_id, &a_pk)),
                NOW
            )
            .unwrap_err(),
            RatchetSpliceError::Ratchet(RatchetError::AuthFailed),
        );
        assert_eq!(*b.store.export(&key).expect("held"), *before);
        assert_eq!(
            open(
                &b.store,
                &b.me(),
                &a.node_id,
                &good,
                Some(&dev(a.instance_id, &a_pk)),
                NOW
            )
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
        let reply = seal(&b.store, &b.me(), keys(&a, &aek, &apk), b"hi", NOW)
            .expect("seal")
            .0;
        let b_pk = b.ratchet_pk();
        open(
            &a.store,
            &a.me(),
            &b.node_id,
            &reply,
            Some(&dev(b.instance_id, &b_pk)),
            NOW,
        )
        .expect("open");
        let bare = seal(&a.store, &a.me(), keys(&b, &ek, &pk), b"two", NOW)
            .expect("seal")
            .0;
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
        let good = seal(&a.store, &a.me(), keys(&b, &ek, &pk), b"two", NOW)
            .expect("seal")
            .0;

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
        assert!(
            open(
                &b.store,
                &b.me(),
                &a.node_id,
                &forged,
                Some(&dev(a.instance_id, &a_pk)),
                NOW
            )
            .is_err()
        );

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
            open(
                &b.store,
                &b.me(),
                &a.node_id,
                &good,
                Some(&dev(a.instance_id, &a_pk)),
                NOW
            )
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
        let payload = seal(&a.store, &a.me(), keys(&b, &ek, &pk), b"x", NOW)
            .expect("seal")
            .0;
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
                dev.store.import(&key, &blob, NOW).expect("import");
            }
        }

        // The conversation continues from exactly where it was.
        let third = seal(&a.store, &a.me(), keys(&b, &ek, &pk), b"three", NOW)
            .expect("seal")
            .0;
        let a_pk = a.ratchet_pk();
        let got = open(
            &b.store,
            &b.me(),
            &a.node_id,
            &third,
            Some(&dev(a.instance_id, &a_pk)),
            NOW,
        )
        .expect("open");
        assert_eq!(got.plaintext, b"three");
        assert!(got.authenticated, "the authenticated flag must survive too");

        let (aek, apk) = (a.ek(), a.ratchet_pk());
        let back = seal(&b.store, &b.me(), keys(&a, &aek, &apk), b"four", NOW)
            .expect("seal")
            .0;
        let b_pk = b.ratchet_pk();
        assert_eq!(
            open(
                &a.store,
                &a.me(),
                &b.node_id,
                &back,
                Some(&dev(b.instance_id, &b_pk)),
                NOW
            )
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
        let lost = seal(&a.store, &a.me(), keys(&b, &ek, &pk), b"lost", NOW)
            .expect("seal")
            .0;
        drop(lost);

        let key = a.store.keys()[0];
        let blob = a.store.export(&key).expect("held");
        let restarted = RatchetStore::new();
        restarted.import(&key, &blob, NOW).expect("import");

        let again = seal(&restarted, &a.me(), keys(&b, &ek, &pk), b"again", NOW)
            .expect("seal")
            .0;
        assert_eq!(again[2], KIND_PROLOGUE);
        let a_pk = a.ratchet_pk();
        assert_eq!(
            open(
                &b.store,
                &b.me(),
                &a.node_id,
                &again,
                Some(&dev(a.instance_id, &a_pk)),
                NOW
            )
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
        let payload = seal(&a.store, &a.me(), keys(&b, &ek, &pk), b"x", NOW)
            .expect("seal")
            .0;
        assert_eq!(a.store.version(), 1);
        let dirty = a.store.drain_dirty();
        assert_eq!(dirty.len(), 1);
        assert_eq!(dirty[0].peer_node_id, b.node_id);
        assert!(
            a.store.drain_dirty().is_empty(),
            "draining must clear, or a host cannot tell new work from old"
        );

        let a_pk = a.ratchet_pk();
        open(
            &b.store,
            &b.me(),
            &a.node_id,
            &payload,
            Some(&dev(a.instance_id, &a_pk)),
            NOW,
        )
        .expect("open");
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
            seal(&a.store, &a.me(), keys(b, &ek, &pk), b"x", NOW).expect("seal");
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
            seal(&a.store, &a.me(), keys(b, &ek, &pk), b"x", NOW).expect("seal");
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
            seal(&a.store, &a.me(), keys(b, &ek, &pk), b"x", NOW).expect("seal");
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
        seal(&a.store, &a.me(), keys(&b, &ek, &pk), b"first", NOW).expect("seal");

        let (batch, generation) = a.store.peek_dirty(99);
        assert_eq!(batch.len(), 1);

        // The send that lands while the write for the previous one is in flight.
        seal(&a.store, &a.me(), keys(&b, &ek, &pk), b"second", NOW).expect("seal");

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
        seal(&a.store, &a.me(), keys(&b, &ek, &pk), b"x", NOW).expect("seal");

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
        let payload = seal(&a.store, &a.me(), keys(&b, &ek, &pk), b"pre-rotation", NOW)
            .expect("seal")
            .0;

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
            open(
                &b.store,
                &b.me(),
                &a.node_id,
                &payload,
                Some(&dev(a.instance_id, &a_pk)),
                NOW
            )
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
            seal(&a.store, &a.me(), keys(&b, &ek, &zero), b"x", NOW).unwrap_err(),
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
            seal(&a.store, &a.me(), keys(&b, &ek, &pk), b"deliver me", NOW).expect("seal");
        assert_ne!(sent_key, [0u8; ACK_KEY_LEN]);
        assert!(
            !payload
                .windows(ACK_KEY_LEN)
                .any(|w| w == sent_key.as_slice()),
            "the ack key must be INSIDE the ciphertext, not beside it"
        );

        let a_pk = a.ratchet_pk();
        let got = open(
            &b.store,
            &b.me(),
            &a.node_id,
            &payload,
            Some(&dev(a.instance_id, &a_pk)),
            NOW,
        )
        .expect("open");
        assert_eq!(got.ack_key, sent_key);
        assert_eq!(got.plaintext, b"deliver me", "and must not leak into it");

        // Every message gets its own.
        let (_, second_key) =
            seal(&a.store, &a.me(), keys(&b, &ek, &pk), b"again", NOW).expect("seal");
        assert_ne!(second_key, sent_key);
    }

    // ── Quota, expiry, pagination ────────────────────────────────────────────

    /// Put `n` conversations into `store` directly, at `last_used_at = stamp`.
    ///
    /// Built by hand rather than by running `seal`/`open` a thousand times:
    /// filling the store through the real paths costs a PQXDH per entry and
    /// minutes per test. The entries are the real type and the admission rules
    /// are exercised separately by the tests that drive `seal` and `open`.
    fn plant(
        store: &RatchetStore,
        n: usize,
        authenticated: bool,
        stamp: u64,
        tag: u8,
    ) -> Vec<ConversationKey> {
        let (a, b) = (device(0x01), device(0x02));
        let (ek, pk) = (b.ek(), b.ratchet_pk());
        let blob = {
            seal(&a.store, &a.me(), keys(&b, &ek, &pk), b"x", NOW).expect("seal");
            a.store.export(&a.store.keys()[0]).expect("held")
        };
        let mut planted = Vec::with_capacity(n);
        let mut g = store.lock();
        for i in 0..n {
            // `tag` namespaces one call's keys away from another's, so a test
            // that plants two groups gets two groups and not one overwritten
            // by the other.
            let mut key = ConversationKey {
                local_instance_id: [0x11; 16],
                peer_node_id: [0x22; 32],
                peer_instance_id: [tag; 16],
            };
            key.peer_node_id[..8].copy_from_slice(&(i as u64).to_be_bytes());
            let mut entry = Entry::decode(&blob).expect("decode");
            // Said outright rather than implied by a zero stamp. The blob this
            // is cut from belongs to a conversation that WAS proven, so its
            // history bit is set; zeroing the stamp alone now describes a
            // conversation restored from an older build, which is a different
            // thing and deliberately not droppable.
            entry.proven_before = false;
            entry.authenticated_until = if authenticated { u64::MAX } else { 0 };
            entry.pending_prologue = None;
            entry.last_used_at = stamp;
            g.entries.insert(key, entry);
            planted.push(key);
        }
        drop(g);
        planted
    }

    #[test]
    fn a_flood_of_unproven_conversations_cannot_grow_past_the_ceiling() {
        // The reason the ceiling exists. A prologue is sealed to keys this
        // device published, so anyone who can reach it can make it hold a
        // session, and the sender pays one encapsulation for each.
        // The literals here are deliberate. A test that compared against the
        // constant would move whenever the constant moved, so raising the
        // ceiling — or the window — would keep it green while the bound it is
        // supposed to pin quietly went somewhere else.
        assert_eq!(MAX_CONVERSATIONS, 1_024, "the documented ceiling");
        assert_eq!(
            UNPROVEN_TTL_SECS,
            14 * 24 * 60 * 60,
            "the documented window, and it must stay longer than the mailbox's \
             seven-day store-and-forward reach"
        );

        let store = RatchetStore::new();
        plant(&store, MAX_CONVERSATIONS, false, NOW, 0xA0);
        assert_eq!(store.len(), 1_024, "the ceiling, spelled out");
        assert_eq!(
            store.len(),
            store.capacity(),
            "the fixture must have filled it exactly"
        );

        // One more, through the real inbound path.
        let (a, b) = (device(0x80), device(0x81));
        let (bek, bpk) = (b.ek(), b.ratchet_pk());
        let payload = seal(&a.store, &a.me(), keys(&b, &bek, &bpk), b"one more", NOW)
            .expect("seal")
            .0;
        let me = RatchetIdentity {
            local_node_id: b.node_id,
            local_instance_id: b.instance_id,
            seed_ring: std::sync::Arc::clone(&b.ring),
        };
        let a_pk = a.ratchet_pk();
        open(
            &store,
            &me,
            &a.node_id,
            &payload,
            Some(&dev(a.instance_id, &a_pk)),
            NOW,
        )
        .expect("open");

        // Held, and the store did not grow: one of the planted entries went.
        assert_eq!(store.len(), 1_024, "the store grew past its ceiling");
        assert!(
            store.has_session(&ConversationKey {
                local_instance_id: b.instance_id,
                peer_node_id: a.node_id,
                peer_instance_id: a.instance_id,
            }),
            "the newcomer was not admitted"
        );
    }

    #[test]
    fn eviction_never_takes_a_conversation_this_device_has_spoken_on() {
        // H-03's lesson as a test. Evicting a proven conversation does not
        // cost a round trip — it wedges that conversation permanently, because
        // the peer's side is proven and answered and `open` refuses to let any
        // prologue re-key one of those. So a full store must take the unproven
        // entry and leave every proven one where it is, and when there is no
        // unproven entry left it must refuse rather than choose a victim.
        let store = RatchetStore::new();
        let proven = plant(&store, MAX_CONVERSATIONS - 1, true, NOW, 0xA1);
        // The single unproven entry, made the NEWEST so that a plain
        // least-recently-used rule would pass over it and take a proven one.
        let unproven = plant(&store, 1, false, NOW + 9_999, 0xA2);
        assert_eq!(store.len(), 1_024);

        let (a, b) = (device(0x82), device(0x83));
        let (bek, bpk) = (b.ek(), b.ratchet_pk());
        let payload = seal(&a.store, &a.me(), keys(&b, &bek, &bpk), b"admit me", NOW)
            .expect("seal")
            .0;
        let me = RatchetIdentity {
            local_node_id: b.node_id,
            local_instance_id: b.instance_id,
            seed_ring: std::sync::Arc::clone(&b.ring),
        };
        let a_pk = a.ratchet_pk();
        open(
            &store,
            &me,
            &a.node_id,
            &payload,
            Some(&dev(a.instance_id, &a_pk)),
            NOW,
        )
        .expect("open");

        assert!(
            !store.has_session(&unproven[0]),
            "the unproven conversation should have been the one to go"
        );
        for (i, key) in proven.iter().enumerate() {
            assert!(
                store.has_session(key),
                "proven conversation {i} was evicted; its peer is now unreachable forever"
            );
        }
    }

    #[test]
    fn a_full_store_of_proven_conversations_refuses_rather_than_evicts() {
        // The end of the line: nothing droppable left. Refusing one new
        // conversation is recoverable — the host forgets something, or the
        // user does. Silently breaking one of the thousand already running is
        // not, and it would be indistinguishable from data loss.
        let store = RatchetStore::new();
        let proven = plant(&store, MAX_CONVERSATIONS, true, NOW, 0xA3);

        let (a, b) = (device(0x84), device(0x85));
        let (bek, bpk) = (b.ek(), b.ratchet_pk());
        let me = RatchetIdentity {
            local_node_id: a.node_id,
            local_instance_id: a.instance_id,
            seed_ring: std::sync::Arc::clone(&a.ring),
        };
        assert_eq!(
            seal(&store, &me, keys(&b, &bek, &bpk), b"no room", NOW).unwrap_err(),
            RatchetSpliceError::StoreFull,
        );
        assert_eq!(store.len(), 1_024);
        for (i, key) in proven.iter().enumerate() {
            assert!(
                store.has_session(key),
                "proven conversation {i} was evicted"
            );
        }

        // And forgetting one makes room again, so the refusal is a full store
        // and not a dead store.
        assert!(store.forget(&proven[0]));
        seal(&store, &me, keys(&b, &bek, &bpk), b"room now", NOW).expect("seal");
    }

    #[test]
    fn a_first_contact_still_waiting_for_its_answer_is_never_evicted() {
        // The case that looks droppable and is the worst one to drop. We have
        // opened a conversation and heard nothing back, so there is no traffic
        // on it and it is the obvious thing for a cache to discard — and
        // discarding it wedges the contact permanently. The peer receives our
        // prologue, answers, and their side is proven and answered from that
        // moment. Our replacement prologue then meets `open`'s displacement
        // rule, which refuses to re-key a proven answered conversation, and
        // their reply meets a store that has nothing to open it with. Neither
        // end can send anything that recovers the other.
        //
        // So "we have spoken on it" is the test, not "it has carried traffic",
        // and this pins the difference: `pending_prologue` being outstanding
        // makes an entry DISPLACEABLE by the peer who can prove it is theirs,
        // and still not DROPPABLE by us.
        let store = RatchetStore::new();
        let proven = plant(&store, MAX_CONVERSATIONS - 1, true, NOW + 500, 0xB0);
        let outstanding = plant(&store, 1, true, NOW, 0xB1);
        // Make it exactly what an unanswered first contact is, and the oldest
        // entry in the store, so any age-based rule would take it first.
        {
            let mut g = store.lock();
            let entry = g.entries.get_mut(&outstanding[0]).expect("held");
            entry.pending_prologue = Some(vec![0u8; PQXDH_PROLOGUE_LEN]);
        }

        let (a, b) = (device(0x8C), device(0x8D));
        let (bek, bpk) = (b.ek(), b.ratchet_pk());
        let me = RatchetIdentity {
            local_node_id: a.node_id,
            local_instance_id: a.instance_id,
            seed_ring: std::sync::Arc::clone(&a.ring),
        };
        assert_eq!(
            seal(&store, &me, keys(&b, &bek, &bpk), b"someone new", NOW).unwrap_err(),
            RatchetSpliceError::StoreFull,
            "an unanswered first contact was treated as spare room"
        );
        assert!(
            store.has_session(&outstanding[0]),
            "the conversation waiting for its answer was evicted; both ends are \
             now wedged with nothing on the wire that can recover them"
        );
        // And it is still what it was, prologue and all.
        assert!(
            store
                .export(&outstanding[0])
                .map(|b| Entry::decode(&b)
                    .expect("decode")
                    .pending_prologue
                    .is_some())
                .unwrap_or(false),
            "the outstanding prologue did not survive"
        );
        assert_eq!(store.len(), 1_024);
        for (i, key) in proven.iter().enumerate() {
            assert!(
                store.has_session(key),
                "proven conversation {i} was evicted"
            );
        }

        // Time does not take it either: it is not in the class the sweep can
        // touch, however long it waits.
        assert_eq!(store.expire(NOW + 100 * UNPROVEN_TTL_SECS), 0);
        assert!(store.has_session(&outstanding[0]));
    }

    #[test]
    fn a_full_store_still_reads_an_inbound_message_it_cannot_remember() {
        // The inbound half of "nothing droppable left", and the one place the
        // two answers differ. On the send path a refusal is the whole answer.
        // Here the message has ALREADY decrypted under a root only its author
        // could have agreed, so refusing to hand it up would discard a genuine
        // message to protect a memory bound — the wrong trade twice over. So
        // the plaintext goes up and only the session is dropped, and the store
        // neither grows past its ceiling nor gives up a proven conversation to
        // make room for one it was never asked to keep.
        let store = RatchetStore::new();
        let proven = plant(&store, MAX_CONVERSATIONS, true, NOW, 0xAE);

        let (a, b) = (device(0x8E), device(0x8F));
        let (bek, bpk) = (b.ek(), b.ratchet_pk());
        let payload = seal(&a.store, &a.me(), keys(&b, &bek, &bpk), b"read me", NOW)
            .expect("seal")
            .0;
        let me = RatchetIdentity {
            local_node_id: b.node_id,
            local_instance_id: b.instance_id,
            seed_ring: std::sync::Arc::clone(&b.ring),
        };
        let a_pk = a.ratchet_pk();
        let got = open(
            &store,
            &me,
            &a.node_id,
            &payload,
            Some(&dev(a.instance_id, &a_pk)),
            NOW,
        )
        .expect("a genuine message was dropped because the store was full");
        assert_eq!(got.plaintext, b"read me");

        assert_eq!(store.len(), 1_024, "the store grew past its ceiling");
        assert!(
            !store.has_session(&ConversationKey {
                local_instance_id: b.instance_id,
                peer_node_id: a.node_id,
                peer_instance_id: a.instance_id,
            }),
            "there was nothing droppable, so the session must not have been kept"
        );
        for (i, key) in proven.iter().enumerate() {
            assert!(
                store.has_session(key),
                "proven conversation {i} was evicted to store one we were not asked to keep"
            );
        }
    }

    #[test]
    fn a_flood_cannot_deny_the_user_a_new_conversation() {
        // The property that makes the quota safe to have at all, stated end to
        // end: whatever a stranger plants is unproven, so however much of it
        // there is, the user's next outgoing conversation still gets a slot.
        // A quota that could be filled by an attacker would be a denial of
        // service with a different name.
        let store = RatchetStore::new();
        plant(&store, MAX_CONVERSATIONS, false, NOW, 0xA4);

        let a = device(0x86);
        let me = RatchetIdentity {
            local_node_id: a.node_id,
            local_instance_id: a.instance_id,
            seed_ring: std::sync::Arc::clone(&a.ring),
        };
        for i in 0..4u8 {
            let peer = device(0x88 + i);
            let (pek, ppk) = (peer.ek(), peer.ratchet_pk());
            seal(&store, &me, keys(&peer, &pek, &ppk), b"hello", NOW)
                .unwrap_or_else(|e| panic!("a flood denied outgoing conversation {i}: {e}"));
            assert!(store.len() <= 1_024);
        }
    }

    #[test]
    fn an_unproven_conversation_ages_out_and_a_proven_one_never_does() {
        // TTL is measured from last USE. A conversation that carried a message
        // an hour ago is not stale however long ago it was opened, and a quiet
        // one that is proven is not stale at all — there is no way to restart
        // it, so aging it out would strand both ends.
        let store = RatchetStore::new();
        let stale = plant(&store, 3, false, NOW, 0xA5);
        let fresh = plant(&store, 1, false, NOW + 1, 0xA6);
        let proven = plant(&store, 1, true, NOW, 0xA7);

        // One second inside the window: nothing is stale yet.
        assert_eq!(store.expire(NOW + UNPROVEN_TTL_SECS), 0);
        assert_eq!(store.len(), 5);

        // One second past it.
        let dropped = store.expire(NOW + UNPROVEN_TTL_SECS + 1);
        assert_eq!(dropped, 3, "the three idle unproven conversations must go");
        for key in &stale {
            assert!(!store.has_session(key));
        }
        assert!(
            store.has_session(&proven[0]),
            "a proven conversation has no expiry"
        );
        assert!(
            store.has_session(&fresh[0]),
            "a conversation used one second later is not yet stale"
        );

        // Far in the future the proven one is still there, and the unproven
        // one is not.
        store.expire(NOW + 100 * UNPROVEN_TTL_SECS);
        assert!(store.has_session(&proven[0]));
        assert!(!store.has_session(&fresh[0]));
    }

    #[test]
    fn traffic_keeps_a_conversation_alive_and_a_forgery_does_not() {
        // Two halves of "measured from last use". Carrying a message must
        // refresh the stamp, or a long quiet dialogue dies mid-life. A frame
        // that fails to open must NOT, or an attacker aiming garbage at a
        // conversation decides what the sweep spares.
        let (a, b) = (device(0x90), device(0x91));
        let (bek, bpk) = (b.ek(), b.ratchet_pk());
        let first = seal(&a.store, &a.me(), keys(&b, &bek, &bpk), b"hello", NOW)
            .expect("seal")
            .0;
        // Opened WITHOUT Alice's certificate, so Bob's entry stays unproven —
        // the only class the sweep can touch.
        open(&b.store, &b.me(), &a.node_id, &first, None, NOW).expect("open");
        let key = b.store.keys()[0];

        // Most of the way through the window, a genuine message lands.
        let later = NOW + UNPROVEN_TTL_SECS - 10;
        let second = seal(&a.store, &a.me(), keys(&b, &bek, &bpk), b"still here", NOW)
            .expect("seal")
            .0;
        open(&b.store, &b.me(), &a.node_id, &second, None, later).expect("open");

        // The window measured from the ORIGINAL contact has now passed. A
        // conversation stamped at creation would die here.
        assert_eq!(
            b.store.expire(NOW + UNPROVEN_TTL_SECS + 1),
            0,
            "a conversation that carried a message ten seconds ago was aged out"
        );
        assert!(b.store.has_session(&key));

        // A forgery aimed at it, well past the window.
        let third = seal(&a.store, &a.me(), keys(&b, &bek, &bpk), b"forge me", NOW)
            .expect("seal")
            .0;
        let mut forged = third.clone();
        let last = forged.len() - 1;
        forged[last] ^= 0xFF;
        let much_later = later + UNPROVEN_TTL_SECS;
        assert!(open(&b.store, &b.me(), &a.node_id, &forged, None, much_later).is_err());

        // It moved nothing, so the conversation is exactly as stale as the
        // last message it really carried, and now ages out.
        assert_eq!(
            b.store.expire(later + UNPROVEN_TTL_SECS + 1),
            1,
            "a forged frame refreshed the conversation it was aimed at"
        );
        assert!(!b.store.has_session(&key));
    }

    fn stamp_of(store: &RatchetStore, key: &ConversationKey) -> u64 {
        store.lock().entries.get(key).expect("held").last_used_at
    }

    #[test]
    fn sending_marks_a_conversation_used_and_the_stamp_survives_a_restart() {
        // Two things nothing else reaches. `last_used_at` is the last message
        // in EITHER direction, so the send path has to write it — otherwise it
        // is a received-at stamp wearing the wrong name, and any later rule
        // that reads it inherits the lie.
        //
        // And it is persisted rather than reset on import, which is the part
        // that decides whether the sweep ever fires at all: this store lives
        // on a phone, the process restarts many times a day, and a stamp
        // refreshed by hydration would make every conversation permanently
        // one restart old.
        let (a, b) = (device(0x96), device(0x97));
        let (ek, pk) = (b.ek(), b.ratchet_pk());
        seal(&a.store, &a.me(), keys(&b, &ek, &pk), b"one", NOW).expect("seal");
        let key = a.store.keys()[0];
        assert_eq!(stamp_of(&a.store, &key), NOW);

        seal(&a.store, &a.me(), keys(&b, &ek, &pk), b"two", NOW + 1_000).expect("seal");
        assert_eq!(
            stamp_of(&a.store, &key),
            NOW + 1_000,
            "sending did not mark the conversation used"
        );

        // Out to the host's store and back, a long time later.
        let blob = a.store.export(&key).expect("held");
        let restarted = RatchetStore::new();
        restarted
            .import(&key, &blob, NOW + 10_000_000)
            .expect("import");
        assert_eq!(
            stamp_of(&restarted, &key),
            NOW + 1_000,
            "hydrating the store reset the staleness clock"
        );
    }

    #[test]
    fn a_clock_that_steps_backwards_drops_nothing() {
        // `now - last_used` under a saturating subtraction. The safe direction
        // is for a backwards jump to make everything look young: dropping
        // state because a clock resynchronised would be a way to lose mail.
        let store = RatchetStore::new();
        let planted = plant(&store, 2, false, NOW, 0xA8);
        assert_eq!(store.expire(NOW - 10 * UNPROVEN_TTL_SECS), 0);
        assert_eq!(store.expire(0), 0);
        for key in &planted {
            assert!(store.has_session(key));
        }
    }

    #[test]
    fn an_aged_out_conversation_is_named_for_the_host_to_delete() {
        // The store is in memory and the blobs are on the host's disk. A sweep
        // that dropped an entry without saying so would free nothing: the next
        // launch imports exactly what was just aged out.
        let store = RatchetStore::new();
        let planted = plant(&store, 2, false, NOW, 0xA9);
        let before = store.version();
        assert_eq!(store.drain_dirty().len(), 0, "planting marks nothing");

        assert_eq!(store.expire(NOW + UNPROVEN_TTL_SECS + 1), 2);
        assert!(store.version() > before, "a sweep is committed work");
        let named = store.drain_dirty();
        assert_eq!(named.len(), 2);
        for key in &planted {
            assert!(named.contains(key), "an aged-out conversation went unnamed");
            assert!(
                store.export(key).is_none(),
                "and the host must find nothing to write for it"
            );
        }
    }

    #[test]
    fn the_quota_ages_out_before_it_evicts() {
        // Order matters: a store that is merely stale must lose only stale
        // entries, not the least-recently-used live one. Here everything is
        // droppable, so a plain eviction would take exactly one and leave 1023
        // dead conversations behind.
        let store = RatchetStore::new();
        plant(&store, MAX_CONVERSATIONS, false, NOW, 0xAA);

        let (a, b) = (device(0x94), device(0x95));
        let (bek, bpk) = (b.ek(), b.ratchet_pk());
        let me = RatchetIdentity {
            local_node_id: a.node_id,
            local_instance_id: a.instance_id,
            seed_ring: std::sync::Arc::clone(&a.ring),
        };
        seal(
            &store,
            &me,
            keys(&b, &bek, &bpk),
            b"much later",
            NOW + UNPROVEN_TTL_SECS + 1,
        )
        .expect("seal");
        assert_eq!(
            store.len(),
            1,
            "admission evicted one stale conversation instead of sweeping them"
        );
    }

    #[test]
    fn a_conversation_import_respects_the_ceiling() {
        // The host's own disk is not a trusted source of counts either: it is
        // where yesterday's flood was persisted to.
        let store = RatchetStore::new();
        let proven = plant(&store, MAX_CONVERSATIONS, true, NOW, 0xAB);
        let blob = store.export(&proven[0]).expect("held");

        let newcomer = ConversationKey {
            local_instance_id: [0xEE; 16],
            peer_node_id: [0xEE; 32],
            peer_instance_id: [0xEE; 16],
        };
        assert_eq!(
            store.import(&newcomer, &blob, NOW).unwrap_err(),
            RatchetSpliceError::StoreFull
        );
        assert_eq!(store.len(), 1_024);
        // Restoring one already held is not growth, so it always fits.
        store
            .import(&proven[0], &blob, NOW)
            .expect("re-importing a conversation already held must fit");
        assert_eq!(store.len(), 1_024);
    }

    #[test]
    fn a_paginated_walk_names_every_conversation_exactly_once() {
        let store = RatchetStore::new();
        let mut planted = plant(&store, 37, false, NOW, 0xAC);
        planted.sort();

        for page_size in [1usize, 2, 5, 36, 37, 38, 1_000] {
            let mut seen = Vec::new();
            let mut cursor: Option<ConversationKey> = None;
            let mut rounds = 0usize;
            loop {
                let page = store.keys_after(cursor.as_ref(), page_size);
                assert!(page.len() <= page_size, "a page overran {page_size}");
                if page.is_empty() {
                    break;
                }
                cursor = page.last().copied();
                seen.extend(page);
                rounds += 1;
                // A cursor that does not ADVANCE past the key it names walks
                // forever rather than failing an assertion, and a test that
                // hangs is a test that reports nothing.
                assert!(
                    rounds <= planted.len() + 1,
                    "page size {page_size}: the walk did not advance past its cursor"
                );
            }
            assert_eq!(
                seen, planted,
                "page size {page_size} did not walk the store in key order, once each"
            );
        }
    }

    #[test]
    fn a_page_costs_the_page_and_not_the_store() {
        // The point of the cursor. A host with a small buffer must be able to
        // reach the tail; `keys()` only ever hands back the front of the store
        // and a host that could not hold it all had no way to see the rest.
        let store = RatchetStore::new();
        let mut planted = plant(&store, 500, false, NOW, 0xAD);
        planted.sort();

        let front = store.keys_after(None, 4);
        assert_eq!(front, planted[..4]);
        // The tail, reached without ever materialising the middle.
        let mut cursor = planted[planted.len() - 3];
        let tail = store.keys_after(Some(&cursor), 4);
        assert_eq!(
            tail,
            planted[planted.len() - 2..],
            "the tail was unreachable"
        );

        // A cursor naming a conversation that has since gone still resumes at
        // the right place — which is why it is a key and not an offset.
        assert!(store.forget(&cursor));
        assert_eq!(
            store.keys_after(Some(&cursor), 4),
            planted[planted.len() - 2..]
        );

        // And a cursor past the end is the end.
        cursor = ConversationKey {
            local_instance_id: [0xFF; 16],
            peer_node_id: [0xFF; 32],
            peer_instance_id: [0xFF; 16],
        };
        assert!(store.keys_after(Some(&cursor), 4).is_empty());
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
        assert!(fresh.import(&key, &[], NOW).is_err(), "empty accepted");
        assert!(
            fresh.import(&key, &good[..good.len() - 1], NOW).is_err(),
            "truncated accepted"
        );
        let mut trailing = good.to_vec();
        trailing.push(0);
        assert!(
            fresh.import(&key, &trailing, NOW).is_err(),
            "trailing accepted"
        );
        let mut bad_magic = good.to_vec();
        bad_magic[0] = b'X';
        assert!(
            fresh.import(&key, &bad_magic, NOW).is_err(),
            "bad magic accepted"
        );
        let mut bad_version = good.to_vec();
        bad_version[4] = 9;
        assert!(
            fresh.import(&key, &bad_version, NOW).is_err(),
            "bad version accepted"
        );
        assert!(fresh.is_empty(), "no refusal may leave a partial entry");
        fresh
            .import(&key, &good, NOW)
            .expect("the genuine blob imports");
        assert_eq!(fresh.len(), 1);
    }

    #[test]
    fn malformed_payloads_are_refused() {
        let (a, b) = (device(0xB4), device(0xC4));
        let (ek, pk) = (b.ek(), b.ratchet_pk());
        let good = seal(&a.store, &a.me(), keys(&b, &ek, &pk), b"z", NOW)
            .expect("seal")
            .0;
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
                open(
                    &b.store,
                    &b.me(),
                    &a.node_id,
                    &payload,
                    Some(&dev(a.instance_id, &a_pk)),
                    NOW
                )
                .is_err(),
                "{name} was accepted"
            );
        }
        assert!(
            open(
                &b.store,
                &b.me(),
                &a.node_id,
                &good,
                Some(&dev(a.instance_id, &a_pk)),
                NOW
            )
            .is_ok()
        );
    }

    #[test]
    fn the_transcript_carries_no_signature() {
        // Deniability as a property of the bytes on the wire: a payload is a
        // header, a prologue or nothing, one AEAD blob, and no room for
        // anything else. A signature would show up as length.
        let (a, b) = (device(0xB5), device(0xC5));
        let (ek, pk) = (b.ek(), b.ratchet_pk());
        let plaintext = b"the entire message";
        let first = seal(&a.store, &a.me(), keys(&b, &ek, &pk), plaintext, NOW)
            .expect("seal")
            .0;
        // 44 header + 1184 encapsulation key + 16 tag, per the primitive, and
        // the 32-byte delivery-ACK key that rides inside the ciphertext.
        const FRAME_OVERHEAD: usize = 44 + 1184 + 16 + ACK_KEY_LEN;
        assert_eq!(
            first.len(),
            HEADER_LEN + PQXDH_PROLOGUE_LEN + FRAME_OVERHEAD + plaintext.len()
        );
        let a_pk = a.ratchet_pk();
        open(
            &b.store,
            &b.me(),
            &a.node_id,
            &first,
            Some(&dev(a.instance_id, &a_pk)),
            NOW,
        )
        .expect("open");
        let (aek, apk) = (a.ek(), a.ratchet_pk());
        let reply = seal(&b.store, &b.me(), keys(&a, &aek, &apk), b"r", NOW)
            .expect("seal")
            .0;
        let b_pk = b.ratchet_pk();
        open(
            &a.store,
            &a.me(),
            &b.node_id,
            &reply,
            Some(&dev(b.instance_id, &b_pk)),
            NOW,
        )
        .expect("open");
        let second = seal(&a.store, &a.me(), keys(&b, &ek, &pk), plaintext, NOW)
            .expect("seal")
            .0;
        // A bare frame answering an outstanding ciphertext: 1088 more.
        assert_eq!(
            second.len(),
            HEADER_LEN + FRAME_OVERHEAD + 1088 + plaintext.len()
        );
    }
}
