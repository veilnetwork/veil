//! The authenticated session: ratchet plus AEAD, plus the persistence blob.
//!
//! The AEAD lives here rather than in the caller for one reason. A Double
//! Ratchet's receive path mutates state before anyone knows whether the
//! message was genuine — it may turn the epoch, throw away a Diffie-Hellman
//! secret, and bank a run of message keys. If the caller is the one who
//! verifies the tag, then by the time a forgery is detected the session has
//! already been destroyed, and a single injected frame from any relay on the
//! path permanently kills a conversation. So [`RatchetSession::decrypt`] runs
//! the step against a scratch copy and writes it back **only** after the tag
//! verifies. An attacker who cannot produce a valid tag cannot move the state
//! at all.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

use crate::kdf::message_keys;
use crate::pq::{ML_KEM_768_CT_LEN, ML_KEM_768_EK_LEN, ML_KEM_768_SEED_LEN};
use crate::ratchet::{Header, RatchetCore, SendMode, TreeParts};
use crate::tree::{Holes, MAX_TREE_NODES_PER_CHAIN, MAX_TREE_NODES_TOTAL};
use crate::{KEY_LEN, RatchetError, RatchetRng};

/// Frame tag. `VR` for veil ratchet; the version byte follows.
pub const RATCHET_FRAME_MAGIC: [u8; 2] = *b"VR";
/// Persisted-state tag.
///
/// Its first two bytes differ from [`RATCHET_FRAME_MAGIC`], so the frame
/// parser rejects a state blob on its tag rather than on anything downstream,
/// and the state parser does the same with a frame. A stored session and a
/// message on the wire are very different things to confuse.
pub const RATCHET_STATE_MAGIC: [u8; 4] = *b"VSR1";

const FRAME_V1: u8 = 1;
const STATE_V1: u8 = 1;
/// Version 1 plus the tree-mode section at the END, so everything up to and
/// including the pending ciphertext keeps its offset — a host reading the
/// sending counter out of a stored state finds it where it always was.
const STATE_V2: u8 = 2;

/// One stored tree node: `start (4) | depth (1) | key (32)`.
const TREE_NODE_LEN: usize = 4 + 1 + KEY_LEN;

/// `magic(2) ‖ version(1) ‖ flags(1) ‖ dh_pk(32) ‖ pn(4) ‖ n(4)`
const FRAME_FIXED_LEN: usize = 2 + 1 + 1 + 32 + 4 + 4;
const AEAD_TAG_LEN: usize = 16;

const FLAG_EK: u8 = 0b01;
const FLAG_CT: u8 = 0b10;
/// This frame's chain is a key tree. Sent only to a peer that announced it can
/// open one: a build that predates it refuses the frame on this bit alone.
const FLAG_TREE: u8 = 0b100;

/// One end of a ratcheted conversation.
///
/// Cheap to construct from [`import_state`](Self::import_state) and cheap to
/// serialize back with [`export_state`](Self::export_state); everything in
/// between is in memory. It holds no handles and does no I/O.
#[derive(Debug)]
pub struct RatchetSession {
    core: RatchetCore,
}

impl RatchetSession {
    /// How many skipped message keys this session banks — a COUNT, never the
    /// keys. The host persists the whole session on every advance, and the
    /// bank is the part that grows, so this is what tells a fat stored state
    /// from a thin one.
    #[must_use]
    pub fn skipped_len(&self) -> usize {
        self.core.skipped_len()
    }

    /// See [`RatchetCore::skipped_epochs`].
    #[must_use]
    pub fn skipped_epochs(&self) -> (usize, usize) {
        self.core.skipped_epochs()
    }

    /// See [`RatchetCore::clear_skipped`]. Only for a conversation the caller
    /// has never answered.
    pub fn clear_skipped(&mut self) -> usize {
        self.core.clear_skipped()
    }

    /// See [`RatchetCore::prune_skipped_to_current_epoch`].
    pub fn prune_skipped_to_current_epoch(&mut self) -> usize {
        self.core.prune_skipped_to_current_epoch()
    }

    /// The party that speaks first, keyed from a completed PQXDH.
    pub(crate) fn initiator(
        root: &[u8; KEY_LEN],
        peer_ratchet_pk: &[u8; 32],
        rng: &mut impl RatchetRng,
    ) -> Result<Self, RatchetError> {
        Ok(Self {
            core: RatchetCore::initiator(root, peer_ratchet_pk, rng)?,
        })
    }

    /// The party that is addressed first, keyed from a completed PQXDH.
    pub(crate) fn responder(
        root: &[u8; KEY_LEN],
        our_ratchet_sk: [u8; 32],
        rng: &mut impl RatchetRng,
    ) -> Self {
        Self {
            core: RatchetCore::responder(root, our_ratchet_sk, rng),
        }
    }

    /// Seal one message.
    ///
    /// `associated_data` is bound into the tag but not transmitted; pass the
    /// same bytes on both sides (the sender and recipient identifiers, say) or
    /// pass nothing. The returned frame is self-describing and opaque — the
    /// caller carries it as a payload and nothing else.
    pub fn encrypt(
        &mut self,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, RatchetError> {
        let (header, mk) = self.core.send_step()?;
        let mut frame = encode_header(&header);
        let aad = frame_aad(&frame, associated_data);

        let (key, nonce) = message_keys(&mk);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&*key));
        let sealed = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| RatchetError::AuthFailed)?;
        frame.extend_from_slice(&sealed);
        Ok(frame)
    }

    /// Where the sending chain stands — see [`crate::ratchet::SendPosition`].
    ///
    /// A host records this durably BEFORE it publishes a ciphertext, so that a
    /// write that never lands cannot let a restart re-derive a key this
    /// session already spent on the wire (report12 X-H5). Reserving a small
    /// run at a time keeps that to one small write per run rather than one per
    /// message.
    pub fn send_position(&self) -> Option<crate::ratchet::SendPosition> {
        self.core.send_position()
    }

    /// Burn sending-chain steps until the next message would be `to.next`.
    ///
    /// The recovery half: on start, a state older than the position last
    /// reserved is fast-forwarded past every index that might already have
    /// been spent. Keys burned this way were never emitted, so the peer sees
    /// a gap its skipped-key window absorbs — which costs nothing next to two
    /// ciphertexts under one nonce.
    pub fn skip_send_to(&mut self, to: crate::ratchet::SendPosition) -> Result<u32, RatchetError> {
        self.core.skip_send_to(to)
    }

    /// Open one message.
    ///
    /// On any failure — a forged tag, a malformed frame, a replay, a peer
    /// trying to strip the post-quantum leg — the session is left exactly as
    /// it was. Nothing an attacker can send moves the state.
    pub fn decrypt(
        &mut self,
        frame: &[u8],
        associated_data: &[u8],
        rng: &mut impl RatchetRng,
    ) -> Result<Vec<u8>, RatchetError> {
        let (header, body_at) = decode_header(frame)?;
        let ciphertext = &frame[body_at..];
        if ciphertext.len() < AEAD_TAG_LEN {
            return Err(RatchetError::MalformedFrame("ciphertext shorter than tag"));
        }
        let aad = frame_aad(&frame[..body_at], associated_data);

        // Scratch copy: the step may turn the epoch and bank keys, and none of
        // that may survive a forged tag.
        let mut trial = self.core.clone();
        let mk = trial.recv_step(&header, rng)?;

        let (key, nonce) = message_keys(&mk);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&*key));
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| RatchetError::AuthFailed)?;

        self.core = trial;
        Ok(plaintext)
    }
}

// ── Persistence ──────────────────────────────────────────────────────────────

impl RatchetSession {
    /// Serialize the whole session, secrets included.
    ///
    /// The blob is **canonical**: the same session always produces the same
    /// bytes, because the skipped-key cache is ordered. It is also entirely
    /// secret — every byte of it is key material — so the caller must store it
    /// encrypted. In this project that is xVeil's hidden volume.
    ///
    /// Layout, all integers big-endian:
    ///
    /// ```text
    /// magic "VSR1" (4) | version (1)
    /// | dh_sk (32)
    /// | has_remote (1) | [dh_pk_remote (32)]
    /// | rk (32)
    /// | has_cks (1) | [cks (32)]
    /// | has_ckr (1) | [ckr (32)]
    /// | ns (4) | nr (4) | pn (4) | sent_any (1)
    /// | skipped_count (4)
    /// |   skipped_count × ( peer_dh_pk (32) | index (4) | message_key (32) )
    /// | pq_seed (64)
    /// | has_pending_ct (1) | [pending_ct (1088)]
    /// — version 2 only, from here on:
    /// | peer_tree (1) | send_mode (1: 0 undecided, 1 hash chain, 2 tree)
    /// | recv_tree (1)
    /// | send_node_count (4) | send_node_count × node
    /// | tree_chain_count (4)
    /// |   tree_chain_count × ( peer_dh_pk (32) | node_count (4) | node_count × node )
    /// ```
    ///
    /// where a node is `start (4) | depth (1) | key (32)`, in index order.
    ///
    /// Sizes, all pinned by
    /// [`state_blob_sizes_are_what_the_documentation_claims`](tests::state_blob_sizes_are_what_the_documentation_claims):
    ///
    /// * 165 bytes — a freshly-constructed responder, nothing established.
    /// * 229 bytes — an initiator straight out of key agreement.
    /// * 1 349 bytes — an established session in either direction.
    /// * plus 68 bytes for each message key banked out of order (at most
    ///   [`MAX_SKIP_TOTAL`](crate::MAX_SKIP_TOTAL), so 137 kB in the worst
    ///   case).
    /// * plus, for tree-mode chains, 37 bytes a node — about 32 nodes for a
    ///   chain received in order, and at most
    ///   [`MAX_TREE_NODES_TOTAL`](crate::MAX_TREE_NODES_TOTAL) across the
    ///   conversation, so about 150 kB in the worst case.
    pub fn export_state(&self) -> Zeroizing<Vec<u8>> {
        let p = self.core.parts();
        // EXACTLY, not approximately. `1_300 + skipped * 68` is 38 bytes short
        // of this format's own worst case — 1 338 bytes, as version 1 was — so a
        // session carrying all three optional keys AND a pending ML-KEM
        // ciphertext grew the buffer mid-write. A `Vec` that grows COPIES what
        // it already holds into a new allocation and abandons the old one, and
        // by that point the old one holds the DH secret, the root key and the
        // chain keys: `Zeroizing` wraps the buffer that comes back, never the
        // one left behind (report21 V18-L5).
        //
        // Reserving the exact size makes the growth unreachable rather than
        // unlikely, and the assertion below keeps this arithmetic honest as
        // fields are added.
        let opt32 = |present: bool| 1 + usize::from(present) * 32;
        let exact = RATCHET_STATE_MAGIC.len()
            + 1 // version
            + 32 // dh_sk
            + opt32(p.dh_pk_remote.is_some())
            + KEY_LEN // rk
            + opt32(p.cks.is_some())
            + opt32(p.ckr.is_some())
            + 4 + 4 + 4 // ns, nr, pn
            + 1 // sent_any
            + 4 // skipped count
            + p.skipped.len() * (32 + 4 + KEY_LEN)
            + p.pq_seed.len()
            + 1
            + usize::from(p.pending_ct.is_some()) * ML_KEM_768_CT_LEN
            + 3
            + 4
            + p.tree.send_tree.as_ref().map_or(0, Holes::len) * TREE_NODE_LEN
            + 4
            + p.tree
                .tree_holes
                .values()
                .map(|h| 32 + 4 + h.len() * TREE_NODE_LEN)
                .sum::<usize>();
        let mut out = Vec::with_capacity(exact);

        out.extend_from_slice(&RATCHET_STATE_MAGIC);
        out.push(STATE_V2);
        out.extend_from_slice(&p.dh_sk);
        push_opt32(&mut out, p.dh_pk_remote.as_ref());
        out.extend_from_slice(&p.rk);
        push_opt32(&mut out, p.cks.as_ref());
        push_opt32(&mut out, p.ckr.as_ref());
        out.extend_from_slice(&p.ns.to_be_bytes());
        out.extend_from_slice(&p.nr.to_be_bytes());
        out.extend_from_slice(&p.pn.to_be_bytes());
        out.push(u8::from(p.sent_any));

        out.extend_from_slice(&(p.skipped.len() as u32).to_be_bytes());
        for ((peer_pk, idx), mk) in p.skipped {
            out.extend_from_slice(peer_pk);
            out.extend_from_slice(&idx.to_be_bytes());
            out.extend_from_slice(&**mk);
        }

        out.extend_from_slice(&p.pq_seed);
        match p.pending_ct {
            Some(ct) => {
                out.push(1);
                out.extend_from_slice(&ct);
            }
            None => out.push(0),
        }

        out.push(u8::from(p.tree.peer_tree));
        out.push(match p.tree.send_mode {
            SendMode::Undecided => 0,
            SendMode::Linear => 1,
            SendMode::Tree => 2,
        });
        out.push(u8::from(p.tree.recv_tree));
        match &p.tree.send_tree {
            Some(holes) => push_holes(&mut out, holes),
            None => out.extend_from_slice(&0u32.to_be_bytes()),
        }
        out.extend_from_slice(&(p.tree.tree_holes.len() as u32).to_be_bytes());
        for (peer_pk, holes) in &p.tree.tree_holes {
            out.extend_from_slice(peer_pk);
            push_holes(&mut out, holes);
        }
        debug_assert_eq!(
            out.len(),
            exact,
            "the reserved size no longer matches what is written; a field was \
             added without its bytes, and the buffer will grow mid-write again"
        );
        Zeroizing::new(out)
    }

    /// Rebuild a session from [`export_state`](Self::export_state).
    ///
    /// Rejects anything it does not fully understand: a wrong tag, a wrong
    /// version, a truncation, a trailing byte, an oversized skipped cache, or
    /// a counter beyond the point where the session should have been re-keyed.
    /// A partially-understood session is a session with the wrong keys.
    pub fn import_state(bytes: &[u8]) -> Result<Self, RatchetError> {
        let mut r = Reader::new(bytes);

        if r.take(4)? != RATCHET_STATE_MAGIC {
            return Err(RatchetError::MalformedState("bad magic"));
        }
        let version = r.take_u8()?;
        if version != STATE_V1 && version != STATE_V2 {
            return Err(RatchetError::MalformedState("unsupported version"));
        }

        let dh_sk = r.take_array::<32>()?;
        let dh_pk_remote = r.take_opt32()?;
        let rk = r.take_array::<KEY_LEN>()?;
        let cks = r.take_opt32()?;
        let ckr = r.take_opt32()?;
        let ns = r.take_u32()?;
        let nr = r.take_u32()?;
        let pn = r.take_u32()?;
        let sent_any = match r.take_u8()? {
            0 => false,
            1 => true,
            _ => return Err(RatchetError::MalformedState("bad boolean")),
        };

        // Past this point a chain has run so long that skipping is no longer
        // bounded by anything sane; a session that got here was corrupted or
        // forged, and re-keying is the only correct answer.
        if ns > u32::MAX / 2 || nr > u32::MAX / 2 || pn > u32::MAX / 2 {
            return Err(RatchetError::MalformedState("counter out of range"));
        }

        let count = r.take_u32()? as usize;
        if count > crate::MAX_SKIP_TOTAL {
            return Err(RatchetError::MalformedState("skipped cache over limit"));
        }
        let mut skipped = BTreeMap::new();
        for _ in 0..count {
            let peer_pk = r.take_array::<32>()?;
            let idx = r.take_u32()?;
            let mk = Zeroizing::new(r.take_array::<KEY_LEN>()?);
            skipped.insert((peer_pk, idx), mk);
        }
        if skipped.len() != count {
            return Err(RatchetError::MalformedState("duplicate skipped key"));
        }

        let pq_seed = r.take_array::<ML_KEM_768_SEED_LEN>()?;
        let pending_ct = match r.take_u8()? {
            0 => None,
            1 => Some(r.take_array::<ML_KEM_768_CT_LEN>()?),
            _ => return Err(RatchetError::MalformedState("bad boolean")),
        };
        let tree = if version == STATE_V1 {
            TreeParts::linear(cks.is_some())
        } else {
            take_tree_parts(&mut r, cks.is_some(), ckr.is_some(), dh_pk_remote)?
        };
        r.finish()?;

        Ok(Self {
            core: RatchetCore::from_parts(
                dh_sk,
                dh_pk_remote,
                rk,
                cks,
                ckr,
                ns,
                nr,
                pn,
                sent_any,
                skipped,
                pq_seed,
                pending_ct,
                tree,
            ),
        })
    }

    /// The peer has said it can open tree-mode chains — see
    /// [`RatchetCore::note_peer_tree`]. For the layer that reads it out of an
    /// authenticated plaintext; nothing on the wire sets it.
    pub fn note_peer_supports_tree(&mut self) {
        self.core.note_peer_tree();
    }

    /// Whether [`note_peer_supports_tree`](Self::note_peer_supports_tree) has
    /// been called on this conversation.
    #[must_use]
    pub fn peer_supports_tree(&self) -> bool {
        self.core.peer_tree()
    }
}

fn push_holes(out: &mut Vec<u8>, holes: &Holes) {
    out.extend_from_slice(&(holes.len() as u32).to_be_bytes());
    for (start, depth, key) in holes.nodes() {
        out.extend_from_slice(&start.to_be_bytes());
        out.push(depth);
        out.extend_from_slice(key);
    }
}

fn take_holes(r: &mut Reader<'_>, budget: &mut usize) -> Result<Holes, RatchetError> {
    let count = r.take_u32()? as usize;
    if count > MAX_TREE_NODES_PER_CHAIN || count > *budget {
        return Err(RatchetError::MalformedState("tree over limit"));
    }
    *budget -= count;
    let mut nodes = Vec::with_capacity(count);
    for _ in 0..count {
        let start = r.take_u32()?;
        let depth = r.take_u8()?;
        let key = r.take_array::<KEY_LEN>()?;
        nodes.push((start, depth, key));
    }
    Holes::from_nodes(nodes).map_err(RatchetError::MalformedState)
}

/// The version-2 tail, held to the same shape the live session keeps: a tree
/// sending chain has no hash-chain key beside it, and a tree receiving chain's
/// holes are filed under the peer key it belongs to.
fn take_tree_parts(
    r: &mut Reader<'_>,
    has_cks: bool,
    has_ckr: bool,
    dh_pk_remote: Option<[u8; 32]>,
) -> Result<TreeParts, RatchetError> {
    let take_bool = |r: &mut Reader<'_>| match r.take_u8()? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(RatchetError::MalformedState("bad boolean")),
    };
    let peer_tree = take_bool(r)?;
    let send_mode = match r.take_u8()? {
        0 => SendMode::Undecided,
        1 => SendMode::Linear,
        2 => SendMode::Tree,
        _ => return Err(RatchetError::MalformedState("bad send mode")),
    };
    let recv_tree = take_bool(r)?;

    let mut budget = MAX_TREE_NODES_TOTAL;
    // A sender holds one path, never gaps; the per-chain bound is generous.
    let send_holes = take_holes(r, &mut MAX_TREE_NODES_PER_CHAIN.clone())?;
    let send_tree = match send_mode {
        SendMode::Tree if !has_cks => Some(send_holes),
        SendMode::Tree => {
            return Err(RatchetError::MalformedState(
                "tree chain beside a chain key",
            ));
        }
        _ if !send_holes.is_empty() => {
            return Err(RatchetError::MalformedState("tree nodes for a hash chain"));
        }
        _ => None,
    };

    let chains = r.take_u32()? as usize;
    // The current chain and the one before it; the step ages out the rest.
    if chains > 2 {
        return Err(RatchetError::MalformedState("too many tree chains"));
    }
    let mut tree_holes = BTreeMap::new();
    for _ in 0..chains {
        let peer_pk = r.take_array::<32>()?;
        let holes = take_holes(r, &mut budget)?;
        if tree_holes.insert(peer_pk, holes).is_some() {
            return Err(RatchetError::MalformedState("duplicate tree chain"));
        }
    }
    if recv_tree && (has_ckr || dh_pk_remote.is_none_or(|pk| !tree_holes.contains_key(&pk))) {
        return Err(RatchetError::MalformedState(
            "tree receiving chain without its holes",
        ));
    }
    Ok(TreeParts {
        peer_tree,
        send_mode,
        send_tree,
        recv_tree,
        tree_holes,
    })
}

// ── Frame codec ──────────────────────────────────────────────────────────────

fn encode_header(h: &Header) -> Vec<u8> {
    let mut flags = 0u8;
    if h.pq_ek.is_some() {
        flags |= FLAG_EK;
    }
    if h.pq_ct.is_some() {
        flags |= FLAG_CT;
    }
    if h.tree {
        flags |= FLAG_TREE;
    }

    let mut out = Vec::with_capacity(
        FRAME_FIXED_LEN
            + h.pq_ek.map_or(0, |_| ML_KEM_768_EK_LEN)
            + h.pq_ct.map_or(0, |_| ML_KEM_768_CT_LEN),
    );
    out.extend_from_slice(&RATCHET_FRAME_MAGIC);
    out.push(FRAME_V1);
    out.push(flags);
    out.extend_from_slice(&h.dh_pk);
    out.extend_from_slice(&h.pn.to_be_bytes());
    out.extend_from_slice(&h.n.to_be_bytes());
    if let Some(ek) = &h.pq_ek {
        out.extend_from_slice(ek);
    }
    if let Some(ct) = &h.pq_ct {
        out.extend_from_slice(ct);
    }
    out
}

/// Returns the header and the offset at which the ciphertext starts.
fn decode_header(frame: &[u8]) -> Result<(Header, usize), RatchetError> {
    if frame.len() < FRAME_FIXED_LEN {
        return Err(RatchetError::MalformedFrame("shorter than a header"));
    }
    if frame[..2] != RATCHET_FRAME_MAGIC {
        return Err(RatchetError::MalformedFrame("bad magic"));
    }
    if frame[2] != FRAME_V1 {
        return Err(RatchetError::MalformedFrame("unsupported version"));
    }
    let flags = frame[3];
    if flags & !(FLAG_EK | FLAG_CT | FLAG_TREE) != 0 {
        return Err(RatchetError::MalformedFrame("unknown flags"));
    }

    let mut dh_pk = [0u8; 32];
    dh_pk.copy_from_slice(&frame[4..36]);
    let pn = u32::from_be_bytes(frame[36..40].try_into().expect("checked length"));
    let n = u32::from_be_bytes(frame[40..44].try_into().expect("checked length"));

    let mut at = FRAME_FIXED_LEN;
    let pq_ek = if flags & FLAG_EK != 0 {
        let end = at + ML_KEM_768_EK_LEN;
        if frame.len() < end {
            return Err(RatchetError::MalformedFrame("truncated encapsulation key"));
        }
        let mut ek = [0u8; ML_KEM_768_EK_LEN];
        ek.copy_from_slice(&frame[at..end]);
        at = end;
        Some(ek)
    } else {
        None
    };
    let pq_ct = if flags & FLAG_CT != 0 {
        let end = at + ML_KEM_768_CT_LEN;
        if frame.len() < end {
            return Err(RatchetError::MalformedFrame("truncated ciphertext"));
        }
        let mut ct = [0u8; ML_KEM_768_CT_LEN];
        ct.copy_from_slice(&frame[at..end]);
        at = end;
        Some(ct)
    } else {
        None
    };

    Ok((
        Header {
            dh_pk,
            pn,
            n,
            pq_ek,
            pq_ct,
            tree: flags & FLAG_TREE != 0,
        },
        at,
    ))
}

/// Everything before the ciphertext is authenticated, plus whatever the caller
/// binds in. Length-prefixing the header half keeps the two fields from
/// sliding into one another.
fn frame_aad(header_bytes: &[u8], associated_data: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(8 + header_bytes.len() + associated_data.len());
    aad.extend_from_slice(&(header_bytes.len() as u32).to_be_bytes());
    aad.extend_from_slice(header_bytes);
    aad.extend_from_slice(&(associated_data.len() as u32).to_be_bytes());
    aad.extend_from_slice(associated_data);
    aad
}

fn push_opt32(out: &mut Vec<u8>, v: Option<&[u8; 32]>) {
    match v {
        Some(x) => {
            out.push(1);
            out.extend_from_slice(x);
        }
        None => out.push(0),
    }
}

struct Reader<'a> {
    buf: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, at: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], RatchetError> {
        let end = self
            .at
            .checked_add(n)
            .ok_or(RatchetError::MalformedState("length overflow"))?;
        if end > self.buf.len() {
            return Err(RatchetError::MalformedState("truncated"));
        }
        let slice = &self.buf[self.at..end];
        self.at = end;
        Ok(slice)
    }
    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], RatchetError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }
    fn take_u8(&mut self) -> Result<u8, RatchetError> {
        Ok(self.take(1)?[0])
    }
    fn take_u32(&mut self) -> Result<u32, RatchetError> {
        Ok(u32::from_be_bytes(self.take_array::<4>()?))
    }
    fn take_opt32(&mut self) -> Result<Option<[u8; 32]>, RatchetError> {
        match self.take_u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.take_array::<32>()?)),
            _ => Err(RatchetError::MalformedState("bad option flag")),
        }
    }
    fn finish(&self) -> Result<(), RatchetError> {
        if self.at != self.buf.len() {
            return Err(RatchetError::MalformedState("trailing bytes"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TestRng;
    use x25519_dalek::{PublicKey, StaticSecret};

    const AD: &[u8] = b"alice-to-bob";

    fn pair() -> (RatchetSession, RatchetSession, TestRng, TestRng) {
        let root = [0x5Au8; KEY_LEN];
        let mut arng = TestRng::new(0xA2);
        let mut brng = TestRng::new(0xB2);
        let bob_sk = *crate::random_array::<32>(&mut brng);
        let bob_pk = *PublicKey::from(&StaticSecret::from(bob_sk)).as_bytes();
        let alice = RatchetSession::initiator(&root, &bob_pk, &mut arng).expect("contributory");
        let bob = RatchetSession::responder(&root, bob_sk, &mut brng);
        (alice, bob, arng, brng)
    }

    /// report21 V18-L5: the export buffer never grows while it holds keys.
    ///
    /// `Vec::with_capacity(1_300 + skipped * 68)` was 38 bytes short of this
    /// format's own worst case — the doc on `export_state` says 1 338 — so a
    /// session carrying all three optional keys AND a pending ML-KEM
    /// ciphertext grew mid-write. A `Vec` that grows COPIES what it already
    /// holds into a new allocation and abandons the old one, and by then the
    /// old one holds the DH secret, the root key and the chain keys.
    /// `Zeroizing` wraps the buffer that comes back, never the one left
    /// behind.
    ///
    /// `capacity == len` is what says no growth happened: `with_capacity`
    /// hands back exactly what was asked for, and any growth from there
    /// overshoots.
    #[test]
    fn the_exported_state_never_outgrows_the_buffer_it_was_written_into() {
        let (mut a, mut b, mut ar, mut br) = pair();

        // The fresh initiator: a pending ML-KEM ciphertext and the fewest
        // optional keys.
        let fresh = a.export_state();
        assert_eq!(
            fresh.capacity(),
            fresh.len(),
            "the reserved size is not the written size. Short, and the buffer \
             GROWS mid-write: the copy left behind holds the DH secret, the \
             root key and the chain keys, and only the buffer that comes back \
             is zeroized. Long, and this arithmetic has drifted from what is \
             written"
        );

        // An established session in both directions: every optional key set.
        for i in 0..4u8 {
            let f = a.encrypt(&[i; 32], AD).expect("seal");
            b.decrypt(&f, AD, &mut br).expect("open");
            let back = b.encrypt(&[i; 16], AD).expect("seal");
            a.decrypt(&back, AD, &mut ar).expect("open");
        }
        for session in [&a, &b] {
            let state = session.export_state();
            assert_eq!(
                state.capacity(),
                state.len(),
                "an established session grew its export buffer"
            );
        }

        // And with message keys banked out of order, which is the term the old
        // estimate scaled and the fixed part it did not.
        let mut skipping = pair();
        let (ref mut sa, ref mut sb, _, ref mut sbr) = skipping;
        let mut held = Vec::new();
        for i in 0..3u8 {
            held.push(sa.encrypt(&[i; 8], AD).expect("seal"));
        }
        // Open only the LAST, so the two before it are banked.
        sb.decrypt(held.last().expect("frames"), AD, sbr)
            .expect("open");
        let banked = sb.export_state();
        assert_eq!(
            banked.capacity(),
            banked.len(),
            "a session holding skipped message keys grew its export buffer"
        );
        // Vacuity: the skipped keys really are in there, or this case is the
        // same as the one above it.
        assert!(
            banked.len() > 68,
            "premise: the banked keys are part of what was written"
        );

        // AND THE OLD ESTIMATE REALLY WAS SHORT, measured rather than argued:
        // the fixed part of an established session with a pending ciphertext
        // exceeds the 1 300 bytes that used to be reserved for it, so the
        // growth this test forbids was reachable in ordinary use.
        let widest = a.export_state();
        // Measured, not argued: an established session is 1 338 bytes against
        // the 1 300 that used to be reserved, so this grew on EVERY established
        // conversation rather than in some exotic corner.
        assert!(
            widest.len() > 1_300 || fresh.len() > 1_300,
            "PREMISE FAILED: neither shape exceeds the old 1 300-byte \
             reservation, so this guard pins something that could not have \
             gone wrong. len fresh={} established={}",
            fresh.len(),
            widest.len()
        );
    }

    #[test]
    fn round_trip() {
        let (mut a, mut b, _ar, mut br) = pair();
        let frame = a.encrypt(b"hello", AD).expect("seal");
        assert_eq!(b.decrypt(&frame, AD, &mut br).expect("open"), b"hello");
    }

    #[test]
    fn a_conversation_flows_both_ways() {
        let (mut a, mut b, mut ar, mut br) = pair();
        for i in 0..8u8 {
            let out = vec![i; 40];
            let f = a.encrypt(&out, AD).expect("seal");
            assert_eq!(b.decrypt(&f, AD, &mut br).expect("open"), out);
            let back = vec![i.wrapping_add(100); 17];
            let f = b.encrypt(&back, AD).expect("seal");
            assert_eq!(a.decrypt(&f, AD, &mut ar).expect("open"), back);
        }
    }

    /// report12 X-H5: the state behind a published ciphertext used to be
    /// written AFTER the frame went out, and the write was allowed to fail.
    /// A restart then brought back the state from before the send, and the
    /// next message re-derived the very key and nonce that frame already used
    /// — for different plaintext. Two ciphertexts under one nonce hand anyone
    /// who sees both the XOR of their plaintexts.
    ///
    /// The position is small enough to record BEFORE publishing, and it is
    /// what lets a restart step over every index that might already have been
    /// spent.
    #[test]
    fn a_restart_behind_a_recorded_position_never_reuses_a_key() {
        let (mut a, mut b, _ar, mut br) = pair();

        // What a host would keep: the state as last written, and a position
        // reserved a little ahead of it.
        let stale_state = a.export_state();
        let reserved = a.send_position().expect("a sending chain exists");
        let reserved = crate::ratchet::SendPosition {
            next: reserved.next + 4,
            ..reserved
        };

        // Four frames go out. Their state never reaches disk.
        let published: Vec<Vec<u8>> = (0..4)
            .map(|i| a.encrypt(&[i as u8; 24], AD).expect("seal"))
            .collect();

        // The crash: everything since the last write is gone.
        let mut recovered = RatchetSession::import_state(&stale_state).expect("import");
        let burned = recovered.skip_send_to(reserved).expect("skip");
        assert_eq!(burned, 4, "the recovered chain must step over all four");

        let after = recovered.encrypt(b"after the restart", AD).expect("seal");
        for (i, earlier) in published.iter().enumerate() {
            assert_ne!(
                &after[..],
                &earlier[..],
                "frame {i} and the post-restart frame are the same bytes"
            );
        }

        // The real proof is on the peer: it took all four, and it takes this
        // one as the NEXT message rather than a replay of one it has seen.
        for frame in &published {
            b.decrypt(frame, AD, &mut br)
                .expect("peer opens the published frames");
        }
        assert_eq!(
            b.decrypt(&after, AD, &mut br)
                .expect("peer opens the recovered frame"),
            b"after the restart",
        );
    }

    /// Without the skip, that same restart walks straight back over a key it
    /// already spent — and the peer refuses the frame as one it has seen.
    #[test]
    fn a_restart_without_the_skip_reuses_an_index() {
        let (mut a, mut b, _ar, mut br) = pair();
        let stale_state = a.export_state();
        let first = a.encrypt(b"the published one", AD).expect("seal");

        let mut recovered = RatchetSession::import_state(&stale_state).expect("import");
        let reused = recovered
            .encrypt(b"a different plaintext", AD)
            .expect("seal");

        b.decrypt(&first, AD, &mut br)
            .expect("peer opens the published frame");
        assert!(
            b.decrypt(&reused, AD, &mut br).is_err(),
            "the peer accepted a second frame at an index it had already \
             consumed — that is the nonce reuse this guards"
        );
    }

    #[test]
    fn a_forged_tag_leaves_the_session_untouched() {
        let (mut a, mut b, _ar, mut br) = pair();
        let good = a.encrypt(b"first", AD).expect("seal");

        let before = b.export_state();

        let mut forged = good.clone();
        let last = forged.len() - 1;
        forged[last] ^= 0xFF;
        assert_eq!(
            b.decrypt(&forged, AD, &mut br).unwrap_err(),
            RatchetError::AuthFailed
        );

        assert_eq!(
            *b.export_state(),
            *before,
            "a forged frame must not move the state by a single byte"
        );
        // And the genuine message still opens.
        assert_eq!(b.decrypt(&good, AD, &mut br).expect("open"), b"first");
    }

    #[test]
    fn a_forged_epoch_turn_does_not_destroy_the_session() {
        // The attack this defends against: inject a frame carrying a ratchet
        // key the peer never used. A ratchet that commits before verifying
        // throws away the live Diffie-Hellman secret and the conversation dies.
        let (mut a, mut b, _ar, mut br) = pair();
        let good = a.encrypt(b"real", AD).expect("seal");

        let mut evil = good.clone();
        evil[4] ^= 0x5A; // a different, still-valid-looking ratchet key
        assert!(b.decrypt(&evil, AD, &mut br).is_err());

        assert_eq!(
            b.decrypt(&good, AD, &mut br).expect("session survived"),
            b"real"
        );
    }

    #[test]
    fn associated_data_is_bound() {
        let (mut a, mut b, _ar, mut br) = pair();
        let f = a.encrypt(b"x", b"context-one").expect("seal");
        assert_eq!(
            b.decrypt(&f, b"context-two", &mut br).unwrap_err(),
            RatchetError::AuthFailed
        );
        assert_eq!(b.decrypt(&f, b"context-one", &mut br).expect("open"), b"x");
    }

    #[test]
    fn every_header_field_is_authenticated() {
        let (mut a, mut b, _ar, mut br) = pair();
        let good = a.encrypt(b"payload", AD).expect("seal");

        // dh_pk, pn, n, and the ML-KEM key all sit inside the additional data,
        // so flipping any of them breaks the tag rather than silently steering
        // the key derivation.
        for offset in [4usize, 36, 40, 44, 44 + ML_KEM_768_EK_LEN - 1] {
            let mut bad = good.clone();
            bad[offset] ^= 0x01;
            assert!(
                b.decrypt(&bad, AD, &mut br).is_err(),
                "byte {offset} was not authenticated"
            );
        }
        assert_eq!(b.decrypt(&good, AD, &mut br).expect("open"), b"payload");
    }

    #[test]
    fn stripping_the_post_quantum_leg_is_refused() {
        let (mut a, mut b, _ar, mut br) = pair();
        let good = a.encrypt(b"pq", AD).expect("seal");

        // Rebuild the frame with the encapsulation key removed, exactly as an
        // attacker who wanted a classical-only ratchet would.
        let mut stripped = good[..FRAME_FIXED_LEN].to_vec();
        stripped[3] = 0; // clear both presence flags
        stripped.extend_from_slice(&good[FRAME_FIXED_LEN + ML_KEM_768_EK_LEN..]);

        assert_eq!(
            b.decrypt(&stripped, AD, &mut br).unwrap_err(),
            RatchetError::PqDowngrade,
            "a header with no ML-KEM leg must be refused outright, not accepted \
             with a classical-only derivation"
        );
    }

    #[test]
    fn malformed_frames_are_refused() {
        let (mut a, mut b, _ar, mut br) = pair();
        let good = a.encrypt(b"z", AD).expect("seal");

        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("empty", vec![]),
            ("truncated header", good[..10].to_vec()),
            ("bad magic", {
                let mut v = good.clone();
                v[0] = b'X';
                v
            }),
            ("bad version", {
                let mut v = good.clone();
                v[2] = 9;
                v
            }),
            ("unknown flags", {
                let mut v = good.clone();
                v[3] |= 0b1000_0000;
                v
            }),
            ("truncated body", good[..good.len() - 20].to_vec()),
            (
                "no ciphertext",
                good[..FRAME_FIXED_LEN + ML_KEM_768_EK_LEN].to_vec(),
            ),
        ];
        for (name, frame) in cases {
            assert!(
                b.decrypt(&frame, AD, &mut br).is_err(),
                "{name} was accepted"
            );
        }
        assert_eq!(b.decrypt(&good, AD, &mut br).expect("open"), b"z");
    }

    #[test]
    fn out_of_order_and_lost_frames_survive_a_restart() {
        let (mut a, mut b, _ar, mut br) = pair();
        let frames: Vec<_> = (0..6u8)
            .map(|i| a.encrypt(&[i; 8], AD).expect("seal"))
            .collect();

        // Deliver 5 and 0, then persist and reload before the rest.
        assert_eq!(b.decrypt(&frames[5], AD, &mut br).expect("open"), [5u8; 8]);
        assert_eq!(b.decrypt(&frames[0], AD, &mut br).expect("open"), [0u8; 8]);

        let blob = b.export_state();
        let mut b2 = RatchetSession::import_state(&blob).expect("reload");

        for i in [3usize, 1, 4, 2] {
            assert_eq!(
                b2.decrypt(&frames[i], AD, &mut br).expect("open"),
                [i as u8; 8],
                "frame {i} did not survive the restart"
            );
        }
    }

    #[test]
    fn state_export_is_canonical_and_round_trips() {
        let (mut a, mut b, _ar, mut br) = pair();
        // Bank several keys, not one: with a single entry every iteration
        // order looks canonical, and a break-check probe that swapped the
        // ordered map for a hashed one slipped straight through.
        for i in 0..12u8 {
            let f = a.encrypt(&[i; 4], AD).expect("seal");
            if !matches!(i, 2 | 3 | 5 | 8 | 9) {
                b.decrypt(&f, AD, &mut br).expect("open");
            }
        }
        assert!(
            b.core.skipped_len() >= 5,
            "the test must actually exercise several banked keys"
        );

        let first = b.export_state();
        let second = b.export_state();
        assert_eq!(*first, *second, "export must be deterministic");

        let reloaded = RatchetSession::import_state(&first).expect("reload");
        assert_eq!(
            *reloaded.export_state(),
            *first,
            "a round trip must reproduce the blob byte for byte"
        );
    }

    #[test]
    fn a_reloaded_session_continues_the_conversation() {
        let (mut a, mut b, mut ar, mut br) = pair();
        let f = a.encrypt(b"one", AD).expect("seal");
        b.decrypt(&f, AD, &mut br).expect("open");

        let a2 = RatchetSession::import_state(&a.export_state()).expect("reload a");
        let b2 = RatchetSession::import_state(&b.export_state()).expect("reload b");
        let (mut a, mut b) = (a2, b2);

        let f = b.encrypt(b"two", AD).expect("seal");
        assert_eq!(a.decrypt(&f, AD, &mut ar).expect("open"), b"two");
        let f = a.encrypt(b"three", AD).expect("seal");
        assert_eq!(b.decrypt(&f, AD, &mut br).expect("open"), b"three");
    }

    #[test]
    fn corrupt_state_blobs_are_refused() {
        let (mut a, mut b, _ar, mut br) = pair();
        let f = a.encrypt(b"x", AD).expect("seal");
        b.decrypt(&f, AD, &mut br).expect("open");
        let good = b.export_state();

        assert!(RatchetSession::import_state(&[]).is_err(), "empty accepted");
        assert!(
            RatchetSession::import_state(&good[..good.len() - 1]).is_err(),
            "truncated accepted"
        );

        let mut trailing = good.to_vec();
        trailing.push(0);
        assert!(
            RatchetSession::import_state(&trailing).is_err(),
            "trailing bytes accepted"
        );

        let mut bad_magic = good.to_vec();
        bad_magic[0] = b'X';
        assert!(
            RatchetSession::import_state(&bad_magic).is_err(),
            "bad magic accepted"
        );

        let mut bad_version = good.to_vec();
        bad_version[4] = 9;
        assert!(
            RatchetSession::import_state(&bad_version).is_err(),
            "bad version accepted"
        );

        // A skipped-cache count beyond the cap must be refused before the
        // reader tries to allocate for it.
        let mut huge = good.to_vec();
        let count_at = 4 + 1 + 32 + 1 + 32 + 32 + 33 + 33 + 4 + 4 + 4 + 1;
        huge[count_at..count_at + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(
            RatchetSession::import_state(&huge).is_err(),
            "oversized skipped cache accepted"
        );
    }

    #[test]
    fn a_state_blob_is_not_a_frame_and_a_frame_is_not_a_state_blob() {
        let (mut a, mut b, _ar, mut br) = pair();
        let frame = a.encrypt(b"x", AD).expect("seal");
        let blob = b.export_state();

        assert!(RatchetSession::import_state(&frame).is_err());
        assert!(b.decrypt(&blob, AD, &mut br).is_err());
        assert_ne!(
            RATCHET_STATE_MAGIC[..2],
            RATCHET_FRAME_MAGIC[..],
            "a state blob must fail the frame parser on the tag itself"
        );
    }

    #[test]
    fn transcript_carries_no_signature() {
        // Deniability, stated as a property of the bytes: a frame is exactly a
        // header plus one AEAD blob. Every fixed-size field is accounted for,
        // so there is no room in it for a signature over anything.
        let (mut a, _b, _ar, _br) = pair();
        let plaintext = b"the entire message";
        let frame = a.encrypt(plaintext, AD).expect("seal");

        let expected = FRAME_FIXED_LEN + ML_KEM_768_EK_LEN + plaintext.len() + AEAD_TAG_LEN;
        assert_eq!(
            frame.len(),
            expected,
            "the frame has room for a header, the message, and a 16-byte AEAD \
             tag — and nothing else. Any signature would show up here."
        );

        // The second message adds nothing either.
        let frame2 = a.encrypt(plaintext, AD).expect("seal");
        assert_eq!(frame2.len(), expected);
    }

    #[test]
    fn either_party_can_forge_a_frame_from_the_other() {
        // The operational form of deniability: given only what Bob holds, Bob
        // produces a frame that opens as if Alice had sent it. Nothing in a
        // transcript can therefore prove Alice said anything.
        let root = [0x77u8; KEY_LEN];
        let mut arng = TestRng::new(0xA3);
        let mut brng = TestRng::new(0xB3);
        let bob_sk = *crate::random_array::<32>(&mut brng);
        let bob_pk = *PublicKey::from(&StaticSecret::from(bob_sk)).as_bytes();

        // Bob, alone, plays both roles.
        let mut fake_alice =
            RatchetSession::initiator(&root, &bob_pk, &mut brng).expect("contributory");
        let mut bob = RatchetSession::responder(&root, bob_sk, &mut brng);

        let forged = fake_alice.encrypt(b"I never said this", AD).expect("seal");
        assert_eq!(
            bob.decrypt(&forged, AD, &mut brng).expect("opens"),
            b"I never said this",
            "Bob alone produced a frame indistinguishable from one of Alice's"
        );

        // And it is byte-shaped exactly like a real one.
        let mut real_alice =
            RatchetSession::initiator(&root, &bob_pk, &mut arng).expect("contributory");
        let real = real_alice.encrypt(b"I never said this", AD).expect("seal");
        assert_eq!(forged.len(), real.len());
    }

    #[test]
    fn frame_size_is_what_the_documentation_claims() {
        let (mut a, mut b, _ar, mut br) = pair();
        let f1 = a.encrypt(b"", AD).expect("seal");
        assert_eq!(
            f1.len(),
            FRAME_FIXED_LEN + ML_KEM_768_EK_LEN + AEAD_TAG_LEN,
            "44 header + 1184 encapsulation key + 16 tag = 1244 bytes of overhead \
             on the first epoch"
        );
        b.decrypt(&f1, AD, &mut br).expect("open");

        // Once the epoch has turned, the answer rides along too.
        let f2 = b.encrypt(b"", AD).expect("seal");
        assert_eq!(
            f2.len(),
            FRAME_FIXED_LEN + ML_KEM_768_EK_LEN + ML_KEM_768_CT_LEN + AEAD_TAG_LEN,
            "and 1088 more once a ciphertext is outstanding: 2332 bytes"
        );
    }

    #[test]
    fn state_blob_sizes_are_what_the_documentation_claims() {
        let root = [0x5Au8; KEY_LEN];
        let mut arng = TestRng::new(0xA4);
        let mut brng = TestRng::new(0xB4);
        let bob_sk = *crate::random_array::<32>(&mut brng);
        let bob_pk = *PublicKey::from(&StaticSecret::from(bob_sk)).as_bytes();

        let mut bob = RatchetSession::responder(&root, bob_sk, &mut brng);
        assert_eq!(bob.export_state().len(), 165, "fresh responder");

        let mut alice = RatchetSession::initiator(&root, &bob_pk, &mut arng).expect("contributory");
        assert_eq!(alice.export_state().len(), 229, "initiator after agreement");

        let f = alice.encrypt(b"hi", AD).expect("seal");
        bob.decrypt(&f, AD, &mut brng).expect("open");
        assert_eq!(bob.export_state().len(), 1_349, "established session");

        let f = bob.encrypt(b"back", AD).expect("seal");
        alice.decrypt(&f, AD, &mut arng).expect("open");
        assert_eq!(alice.export_state().len(), 1_349, "established session");

        // Each key banked out of order costs 32 + 4 + 32.
        let before = bob.export_state().len();
        let dropped = alice.encrypt(b"lost", AD).expect("seal");
        let arrived = alice.encrypt(b"kept", AD).expect("seal");
        drop(dropped);
        bob.decrypt(&arrived, AD, &mut brng).expect("open");
        assert_eq!(bob.export_state().len(), before + 68);
    }

    // ── Tree-mode chains ─────────────────────────────────────────────────────

    fn has_tree_flag(frame: &[u8]) -> bool {
        frame[3] & FLAG_TREE != 0
    }

    /// Both sides have heard "I can open trees", and one exchange has turned
    /// each side's sending chain over — the steady state between two builds
    /// that both carry trees. Returns the pair with `a` about to send on a
    /// tree chain.
    fn tree_pair() -> (RatchetSession, RatchetSession, TestRng, TestRng) {
        let (mut a, mut b, mut ar, mut br) = pair();
        let f = a.encrypt(b"hello", AD).expect("seal");
        assert!(!has_tree_flag(&f), "the first chain is a hash chain");
        b.decrypt(&f, AD, &mut br).expect("open");
        b.note_peer_supports_tree();
        let f = b.encrypt(b"hello back", AD).expect("seal");
        assert!(
            has_tree_flag(&f),
            "b heard it before its chain was first used"
        );
        a.decrypt(&f, AD, &mut ar).expect("open");
        a.note_peer_supports_tree();
        (a, b, ar, br)
    }

    /// The transition needs no reset: a live conversation moves to trees at
    /// each side's next new sending chain, and a chain already in use keeps
    /// the mode it started with.
    #[test]
    fn a_conversation_moves_to_trees_at_the_next_chain_without_a_reset() {
        let (mut a, mut b, mut ar, mut br) = pair();
        let f = a.encrypt(b"one", AD).expect("seal");
        b.decrypt(&f, AD, &mut br).expect("open");
        a.note_peer_supports_tree();
        let f = a.encrypt(b"two", AD).expect("seal");
        assert!(
            !has_tree_flag(&f),
            "a chain already in use keeps its mode, or the receiver would have \
             to guess mid-chain"
        );
        b.decrypt(&f, AD, &mut br).expect("open");

        let (mut a, mut b, mut ar2, mut br2) = tree_pair();
        for turn in 0..6u8 {
            let f = a.encrypt(&[turn; 3], AD).expect("seal");
            assert!(has_tree_flag(&f), "turn {turn}: a sends on a tree");
            assert_eq!(b.decrypt(&f, AD, &mut br2).expect("open"), [turn; 3]);
            let f = b.encrypt(&[turn; 5], AD).expect("seal");
            assert!(has_tree_flag(&f), "turn {turn}: b sends on a tree");
            assert_eq!(a.decrypt(&f, AD, &mut ar2).expect("open"), [turn; 5]);
        }
        let _ = (&mut ar, &mut br);
    }

    /// A peer that never said it can open trees never sees the bit — the
    /// whole of the compatibility story, since an older build refuses a frame
    /// on an unknown flag.
    #[test]
    fn a_peer_that_never_announced_trees_never_sees_the_flag() {
        let (mut a, mut b, mut ar, mut br) = pair();
        for turn in 0..8u8 {
            let f = a.encrypt(&[turn], AD).expect("seal");
            assert!(!has_tree_flag(&f));
            b.decrypt(&f, AD, &mut br).expect("open");
            let f = b.encrypt(&[turn], AD).expect("seal");
            assert!(!has_tree_flag(&f));
            a.decrypt(&f, AD, &mut ar).expect("open");
        }
    }

    /// THE POINT OF THE TREE: a gap no hash chain survives. A million indices
    /// burned between two frames — a mailbox holding a week of re-drives —
    /// and the second one still opens, in one derivation walk.
    #[test]
    fn a_gap_of_a_million_opens_on_a_tree_chain() {
        let (mut a, mut b, _ar, mut br) = tree_pair();
        let f = a.encrypt(b"before", AD).expect("seal");
        b.decrypt(&f, AD, &mut br).expect("open");

        let start = a.send_position().expect("chain").next;
        let mut next = start;
        while next < start + 1_000_000 {
            next += crate::MAX_SEND_SKIP;
            a.skip_send_to(crate::SendPosition {
                chain: a.send_position().expect("chain").chain,
                next,
            })
            .expect("a tree skips in one cut");
        }
        let f = a.encrypt(b"after a million", AD).expect("seal");
        assert_eq!(
            b.decrypt(&f, AD, &mut br)
                .expect("a tree chain opens across the gap"),
            b"after a million"
        );
        assert!(
            b.core.skipped_len() <= 64,
            "the gap costs nodes per level, not a key per message: {}",
            b.core.skipped_len()
        );
    }

    /// CONTROL for the test above: the same gap on a hash chain is refused,
    /// or that test proves nothing about trees.
    #[test]
    fn the_same_gap_on_a_hash_chain_is_refused() {
        let (mut a, mut b, _ar, mut br) = pair();
        let f = a.encrypt(b"before", AD).expect("seal");
        b.decrypt(&f, AD, &mut br).expect("open");
        for _ in 0..2 {
            let pos = a.send_position().expect("chain");
            a.skip_send_to(crate::SendPosition {
                chain: pos.chain,
                next: pos.next + crate::MAX_SEND_SKIP,
            })
            .expect("burn");
        }
        let f = a.encrypt(b"after", AD).expect("seal");
        assert!(matches!(
            b.decrypt(&f, AD, &mut br),
            Err(RatchetError::TooManySkipped(_))
        ));
    }

    #[test]
    fn a_replay_on_a_tree_chain_is_refused_and_moves_nothing() {
        let (mut a, mut b, _ar, mut br) = tree_pair();
        let frames: Vec<_> = (0..4u8)
            .map(|i| a.encrypt(&[i], AD).expect("seal"))
            .collect();
        b.decrypt(&frames[2], AD, &mut br).expect("open");
        b.decrypt(&frames[0], AD, &mut br)
            .expect("open, out of order");
        let before = b.export_state();
        for i in [2usize, 0] {
            assert_eq!(
                b.decrypt(&frames[i], AD, &mut br).unwrap_err(),
                RatchetError::MessageKeyUnavailable,
                "frame {i} a second time"
            );
        }
        assert_eq!(*b.export_state(), *before);
        b.decrypt(&frames[1], AD, &mut br)
            .expect("the gap still opens");
        b.decrypt(&frames[3], AD, &mut br)
            .expect("and so does what follows");
    }

    /// The mode bit is part of the authenticated header: flipped in transit it
    /// yields the wrong key, and the frame is refused without moving state.
    #[test]
    fn a_flipped_tree_flag_is_refused_both_ways() {
        let (mut a, mut b, _ar, mut br) = tree_pair();
        // The FIRST frame of a chain is what sets its mode, so a flip there is
        // caught by the tag alone (the wrong mode derives the wrong key).
        let mut first = a.encrypt(b"first", AD).expect("seal");
        first[3] &= !FLAG_TREE;
        let before = b.export_state();
        assert_eq!(
            b.decrypt(&first, AD, &mut br).unwrap_err(),
            RatchetError::AuthFailed
        );
        assert_eq!(*b.export_state(), *before);
        first[3] |= FLAG_TREE;
        b.decrypt(&first, AD, &mut br)
            .expect("the untouched frame opens");

        let mut f = a.encrypt(b"tree", AD).expect("seal");
        f[3] &= !FLAG_TREE;
        let before = b.export_state();
        // Past the first frame the chain's mode is known, and a frame naming
        // the other one is refused BEFORE any key is derived in it.
        assert_eq!(
            b.decrypt(&f, AD, &mut br).unwrap_err(),
            RatchetError::MalformedFrame("chain mode changed mid-chain"),
            "tree read as a chain"
        );
        assert_eq!(*b.export_state(), *before);

        let (mut a, mut b, _ar, mut br) = pair();
        let mut f = a.encrypt(b"chain", AD).expect("seal");
        f[3] |= FLAG_TREE;
        let before = b.export_state();
        assert!(b.decrypt(&f, AD, &mut br).is_err(), "chain read as a tree");
        assert_eq!(*b.export_state(), *before);
    }

    /// A straggler from the tree chain the peer has since left still opens —
    /// and nothing past the `pn` its successor announced does, because that
    /// part of the old tree was erased when the epoch turned.
    #[test]
    fn a_straggler_from_the_previous_tree_chain_opens_after_the_epoch_turns() {
        let (mut a, mut b, mut ar, mut br) = tree_pair();
        let held: Vec<_> = (0..3u8)
            .map(|i| a.encrypt(&[i], AD).expect("seal"))
            .collect();
        b.decrypt(&held[2], AD, &mut br).expect("open the last");

        // The epoch turns both ways.
        let f = b.encrypt(b"turn", AD).expect("seal");
        a.decrypt(&f, AD, &mut ar).expect("open");
        let f = a.encrypt(b"new chain", AD).expect("seal");
        b.decrypt(&f, AD, &mut br).expect("open");

        assert_eq!(b.decrypt(&held[0], AD, &mut br).expect("late"), [0u8]);
        assert_eq!(b.decrypt(&held[1], AD, &mut br).expect("late"), [1u8]);
        assert!(
            b.core.skipped_len() == 0,
            "the old chain is cut at pn, so once its gaps are filled nothing \
             of it is left: {}",
            b.core.skipped_len()
        );
    }

    #[test]
    fn a_tree_session_survives_a_restart_mid_gap() {
        let (mut a, mut b, _ar, mut br) = tree_pair();
        let frames: Vec<_> = (0..6u8)
            .map(|i| a.encrypt(&[i; 4], AD).expect("seal"))
            .collect();
        b.decrypt(&frames[5], AD, &mut br).expect("open");
        b.decrypt(&frames[1], AD, &mut br).expect("open");

        let blob = b.export_state();
        let mut b2 = RatchetSession::import_state(&blob).expect("reload");
        assert_eq!(*b2.export_state(), *blob, "canonical through a reload");
        assert!(b2.peer_supports_tree(), "what the peer announced is kept");
        for i in [3usize, 0, 4, 2] {
            assert_eq!(
                b2.decrypt(&frames[i], AD, &mut br).expect("open"),
                [i as u8; 4]
            );
        }

        let blob = a.export_state();
        let mut a2 = RatchetSession::import_state(&blob).expect("reload sender");
        let f = a2.encrypt(b"after the sender restarted", AD).expect("seal");
        assert!(has_tree_flag(&f));
        b2.decrypt(&f, AD, &mut br).expect("open");
    }

    /// Version 1 — every stored conversation from before trees — is read as
    /// hash chains and carries on exactly as it would have.
    #[test]
    fn a_version_1_state_is_read_as_hash_chains() {
        let (mut a, mut b, mut ar, mut br) = pair();
        let f = a.encrypt(b"x", AD).expect("seal");
        b.decrypt(&f, AD, &mut br).expect("open");
        let f = b.encrypt(b"y", AD).expect("seal");
        a.decrypt(&f, AD, &mut ar).expect("open");

        // A version-2 state with no tree in it is version 1 plus an 11-byte
        // tail; cut the tail and relabel, and it is what a v1 build wrote.
        let v2 = a.export_state();
        let mut v1 = v2[..v2.len() - 11].to_vec();
        v1[4] = STATE_V1;
        let mut a1 = RatchetSession::import_state(&v1).expect("v1 is still read");
        assert!(!a1.peer_supports_tree());
        a1.note_peer_supports_tree();
        let f = a1.encrypt(b"z", AD).expect("seal");
        assert!(
            !has_tree_flag(&f),
            "a chain stored by v1 may already have been used as a hash chain"
        );
        assert_eq!(b.decrypt(&f, AD, &mut br).expect("open"), b"z");
    }

    /// Many separate runs of loss run into the node ceiling, and the frame
    /// that would cross it is refused without moving the state.
    #[test]
    fn separate_gaps_hit_the_node_ceiling_and_leave_the_state_untouched() {
        let (mut a, mut b, _ar, mut br) = tree_pair();
        let mut refused = false;
        for _ in 0..400 {
            let pos = a.send_position().expect("chain");
            a.skip_send_to(crate::SendPosition {
                chain: pos.chain,
                next: pos.next + 997,
            })
            .expect("skip");
            let f = a.encrypt(b"g", AD).expect("seal");
            let before = b.export_state();
            match b.decrypt(&f, AD, &mut br) {
                Ok(_) => {}
                Err(RatchetError::TooManySkipped(n)) => {
                    assert!(n > crate::MAX_TREE_NODES_PER_CHAIN);
                    assert_eq!(*b.export_state(), *before);
                    refused = true;
                    break;
                }
                Err(e) => panic!("unexpected {e}"),
            }
        }
        assert!(refused, "400 separate gaps never reached the ceiling");
    }

    /// The bank the host budgets is the GAPS, never the path to what is still
    /// to come: clearing it must leave the chain able to receive.
    #[test]
    fn clearing_the_bank_keeps_a_tree_chain_alive() {
        let (mut a, mut b, _ar, mut br) = tree_pair();
        let frames: Vec<_> = (0..4u8)
            .map(|i| a.encrypt(&[i], AD).expect("seal"))
            .collect();
        b.decrypt(&frames[3], AD, &mut br).expect("open");
        assert!(
            b.skipped_len() > 0,
            "three gaps behind the highest received"
        );
        assert!(b.clear_skipped() > 0);
        assert_eq!(b.skipped_len(), 0);
        assert!(
            b.decrypt(&frames[1], AD, &mut br).is_err(),
            "the gap is gone"
        );
        let f = a.encrypt(b"next", AD).expect("seal");
        assert_eq!(b.decrypt(&f, AD, &mut br).expect("chain alive"), b"next");
    }

    #[test]
    fn inconsistent_version_2_states_are_refused() {
        // A hash-chain sender whose state claims a tree: its tail is the bare
        // 11 bytes (no nodes), so the send-mode byte sits 10 from the end.
        let (mut h, _hb, _har, _hbr) = pair();
        h.encrypt(b"a hash chain in use", AD).expect("seal");
        let linear = h.export_state();
        assert_eq!(
            linear[linear.len() - 10],
            1,
            "vacuity guard: send mode Linear"
        );
        let mut claims_tree = linear.to_vec();
        claims_tree[linear.len() - 10] = 2;
        assert!(
            RatchetSession::import_state(&claims_tree).is_err(),
            "a tree sending chain beside a hash-chain key must not load"
        );

        let (mut a, _b, _ar, _br) = tree_pair();
        a.encrypt(b"settles the mode", AD).expect("seal");
        let good = a.export_state();
        RatchetSession::import_state(&good).expect("the unmodified blob loads");
        // The tail: peer_tree | send_mode | recv_tree | send nodes | chains.
        // `a` is on a tree sending chain; claim it is a hash chain.
        let tail_at = good.len()
            - (3 + 4
                + a.core.parts().tree.send_tree.as_ref().map_or(0, Holes::len) * TREE_NODE_LEN
                + 4
                + a.core
                    .parts()
                    .tree
                    .tree_holes
                    .values()
                    .map(|h| 36 + h.len() * TREE_NODE_LEN)
                    .sum::<usize>());
        assert_eq!(good[tail_at + 1], 2, "vacuity guard: this is the send mode");
        for (what, at, value) in [
            ("send mode", tail_at + 1, 1u8),
            ("mode byte", tail_at + 1, 7),
            ("boolean", tail_at, 2),
        ] {
            let mut bad = good.to_vec();
            bad[at] = value;
            assert!(
                RatchetSession::import_state(&bad).is_err(),
                "a state with a bad {what} must not load"
            );
        }
    }

    /// Forward secrecy on the SENDING side: what has been sent, and what a
    /// recorded position skipped, cannot be derived from anything kept.
    #[test]
    fn a_tree_sender_keeps_nothing_behind_it() {
        let (mut a, _b, _ar, _br) = tree_pair();
        for _ in 0..3 {
            a.encrypt(b"sent", AD).expect("seal");
        }
        let held =
            |a: &RatchetSession| a.core.parts().tree.send_tree.expect("a tree sending chain");
        for used in 0..3u32 {
            assert!(
                held(&a).take_leaf(used).is_none(),
                "sent index {used} is still derivable"
            );
        }
        assert!(
            held(&a).len() <= 32,
            "a sender holds one path: {}",
            held(&a).len()
        );

        let pos = a.send_position().expect("chain");
        a.skip_send_to(crate::SendPosition {
            chain: pos.chain,
            next: pos.next + 500,
        })
        .expect("skip");
        for skipped in [pos.next, pos.next + 499] {
            assert!(
                held(&a).take_leaf(skipped).is_none(),
                "skipped index {skipped} is still derivable"
            );
        }
        assert!(
            held(&a).take_leaf(pos.next + 500).is_some(),
            "the mark itself is kept"
        );
    }

    /// Tree chains age by epoch like banked keys: the current one and the one
    /// before it, never more.
    #[test]
    fn tree_chains_age_out_by_epoch() {
        let (mut a, mut b, mut ar, mut br) = tree_pair();
        for turn in 0..5u8 {
            // Each turn leaves a gap in a's chain, so every chain b has seen
            // still holds something.
            let lost = a.encrypt(&[turn], AD).expect("seal");
            drop(lost);
            let f = a.encrypt(&[turn], AD).expect("seal");
            b.decrypt(&f, AD, &mut br).expect("open");
            let f = b.encrypt(&[turn], AD).expect("seal");
            a.decrypt(&f, AD, &mut ar).expect("open");
            assert!(
                b.core.parts().tree.tree_holes.len() <= 2,
                "turn {turn}: {} tree chains held",
                b.core.parts().tree.tree_holes.len()
            );
        }
    }
}
