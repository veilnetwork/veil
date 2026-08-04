//! The node's long-term ML-KEM mailbox key, and the retired keys that must stay
//! decrypt-capable while mail sealed to them can still arrive.
//!
//! ## Why a ring instead of a field
//!
//! The decapsulation seed used to be an `Arc<SensitiveBytesN<64>>` fixed at node
//! start: whatever a node published at boot, it decrypted with until it exited.
//! That makes a leak of those 64 bytes retroactive over the node's whole
//! history — the seed is the one piece of long-lived key material that sits in
//! process memory for hours (the identity seed it derives from is read off disk
//! and dropped, see `identity_local::mlkem_dk::load_or_derive`), so it is the
//! plausible thing to lose to a swap page or a core dump.
//!
//! Rotating it bounds that. But the key's PUBLIC half is published, so the old
//! one cannot simply be discarded: senders hold it, and mail already sealed to
//! it is in flight. Hence a ring — one current key, plus retired keys each
//! carrying the deadline past which nothing can still be sealed to them.
//!
//! ## Why the overlap is days, not hours
//!
//! The obvious window is the live path: a peer caches our EK for
//! `IpcConfig::e2e_key_ttl_secs` (1 h) and a rotated EK reaches the DHT on the
//! sovereign republish tick (6 h). That is the number this file's predecessor
//! recorded, and it is wrong by two orders of magnitude, because it forgets
//! store-and-forward: a relay holds a mailbox blob for `DEFAULT_TTL_SECS`
//! (7 days) before pruning it. A recipient that is offline for a week comes back
//! to mail sealed to the key it published a week ago.
//!
//! Retiring a seed early does not fail loudly. It silently fails to open blobs
//! that were sealed correctly — the exact black-hole shape this codebase has
//! been bitten by before. So [`MlKemSeedRing::rotate`] REFUSES an overlap under
//! [`MLKEM_SEED_MIN_OVERLAP_SECS`] rather than accepting it and losing mail.

use std::sync::RwLock;

use veil_util::sensitive_bytes::SensitiveBytesN;
use zeroize::Zeroizing;

use crate::{DK_SEED_BYTES, EK_BYTES};

/// How long a retired seed must keep decrypting, in seconds.
///
/// The sum of the three ways a blob sealed to an already-replaced EK can still
/// reach us:
///
/// * `veil_mailbox::DEFAULT_TTL_SECS` (7 days) — a relay's mailbox retention;
///   a blob deposited just before we rotated is fetchable for this long.
/// * `IpcConfig::e2e_key_ttl_secs` (1 h) — a sender's cached copy of our EK,
///   which it will keep sealing to without re-resolving.
/// * the sovereign republish interval (6 h) — how long a rotated EK can take to
///   reach the DHT in the worst case. The rotation path shortens this to the
///   on-change poll (60 s), but the constant does not lean on that: a bound
///   that depends on the fast path holding is not a bound.
///
/// `veil-node-runtime` pins this arithmetic against the real constants in a
/// test, so raising the mailbox TTL fails there rather than in the field.
pub const MLKEM_SEED_MIN_OVERLAP_SECS: u64 = 7 * 24 * 3600 + 3600 + 6 * 3600;

/// The relay mailbox retention this overlap has to outlive.
///
/// Duplicated from `veil_mailbox::DEFAULT_TTL_SECS` because that crate sits
/// above this one; `veil-node-runtime` asserts the two agree, so a change there
/// fails the build rather than shortening this window by surprise.
const MAILBOX_RETENTION_SECS: u64 = 7 * 24 * 3600;

// A compile-time guard, not a test: the relationship is the reason the constant
// has the value it has, and getting it wrong loses a week of store-and-forward
// mail rather than failing anywhere visible.
#[allow(clippy::assertions_on_constants)]
const _: () = assert!(
    MLKEM_SEED_MIN_OVERLAP_SECS > MAILBOX_RETENTION_SECS,
    "a retired seed must outlive the relay's mailbox retention",
);

/// Most retired seeds kept at once.
///
/// With a rotation interval at or above the overlap — which is the only
/// configuration [`MlKemSeedRing::rotate`] accepts — at most one retired seed is
/// ever live, so this is a backstop against a caller that rotates in a loop
/// rather than a working limit. Eviction drops the OLDEST, which is the one
/// whose senders are likeliest to have moved on.
pub const MAX_RETIRED_SEEDS: usize = 4;

/// Why a [`MlKemSeedRing::rotate`] was refused.
///
/// Both arms are refusals to do something that would lose mail, so a caller
/// that hits one should log and keep the current key — NOT retry with weaker
/// arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotateRejected {
    /// The requested overlap is under [`MLKEM_SEED_MIN_OVERLAP_SECS`]. Accepting
    /// it would retire a seed while blobs sealed to it are still in mailboxes.
    OverlapTooShort { requested: u64, minimum: u64 },
    /// The requested epoch does not advance on the current one. Installing it
    /// would mean publishing an EK the node believes is newer than it is, and
    /// (for an equal epoch) needlessly retiring a key that is still current.
    EpochNotAdvancing { requested: u64, current: u64 },
}

impl std::fmt::Display for RotateRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OverlapTooShort { requested, minimum } => write!(
                f,
                "overlap {requested}s is under the {minimum}s a sealed mailbox blob can outlive a rotation"
            ),
            Self::EpochNotAdvancing { requested, current } => {
                write!(f, "epoch {requested} does not advance on current {current}")
            }
        }
    }
}

impl std::error::Error for RotateRejected {}

struct RetiredSeed {
    seed: SensitiveBytesN<DK_SEED_BYTES>,
    /// Unix time past which this seed is dropped (and zeroized with it).
    usable_until: u64,
}

struct RingState {
    epoch: u64,
    seed: SensitiveBytesN<DK_SEED_BYTES>,
    ek: [u8; EK_BYTES],
    /// Newest first.
    retired: Vec<RetiredSeed>,
}

/// The node's current ML-KEM mailbox keypair plus its still-usable predecessors.
///
/// One holder, so "which key is current" has a single answer. An earlier sketch
/// kept the EK and the seed in separate fields and added an epoch counter beside
/// them; that is how a node ends up publishing one key and decrypting with
/// another. Here the EK is stored with the seed it belongs to and they are
/// replaced together under one lock.
///
/// `RwLock`, not `Mutex`: every read path (decrypt, publish, handshake) takes a
/// shared guard, and the only writer is the rotation tick.
pub struct MlKemSeedRing {
    state: RwLock<RingState>,
}

impl MlKemSeedRing {
    /// A ring holding just the genesis keypair — the behaviour of the plain
    /// field this type replaced.
    pub fn new(epoch: u64, seed: [u8; DK_SEED_BYTES], ek: [u8; EK_BYTES]) -> Self {
        Self {
            state: RwLock::new(RingState {
                epoch,
                seed: SensitiveBytesN::from_bytes(seed),
                ek,
                retired: Vec::new(),
            }),
        }
    }

    /// The rotation epoch of the current key.
    pub fn epoch(&self) -> u64 {
        self.read().epoch
    }

    /// The encapsulation key to publish and hand to peers.
    ///
    /// Callers overwhelmingly `.to_vec()` this straight into a message, and it
    /// is public material, so it is returned by value rather than behind a
    /// guard — holding the lock across a caller's arbitrary work is the worse
    /// trade at 1184 bytes.
    pub fn current_ek(&self) -> [u8; EK_BYTES] {
        self.read().ek
    }

    /// The seed to seal our own mail under and to build our own cert from.
    ///
    /// Decryption must NOT use this — see [`decrypt_seeds`](Self::decrypt_seeds).
    pub fn current_seed(&self) -> Zeroizing<[u8; DK_SEED_BYTES]> {
        Zeroizing::new(*self.read().seed.as_array())
    }

    /// The device's ratchet X25519 **secret** for the current epoch.
    ///
    /// An encapsulation key authenticates nobody — anyone can encapsulate to
    /// one. This is the Diffie-Hellman key that lets a recipient tell who
    /// wrote to them, and it is derived from the mailbox seed rather than
    /// stored beside it so that the two cannot drift: whatever epoch's seed is
    /// current, this is that epoch's ratchet key, under one lock, with no
    /// second field to forget to update on rotation.
    pub fn current_ratchet_sk(&self) -> Zeroizing<[u8; 32]> {
        veil_crypto::identity::derive_ratchet_x25519_sk(self.read().seed.as_array())
    }

    /// The device's ratchet X25519 **public** key for the current epoch — the
    /// value published in the ML-KEM certificate.
    pub fn current_ratchet_pk(&self) -> [u8; 32] {
        let sk = self.current_ratchet_sk();
        *x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*sk)).as_bytes()
    }

    /// Every ratchet secret a peer could still have addressed a first message
    /// to, current first, then retired newest-first.
    ///
    /// The exact counterpart of [`decrypt_seeds`](Self::decrypt_seeds), and for
    /// the same reason: a sender holding a certificate we published a week ago
    /// derived the root key from the ratchet key in it, and if we have already
    /// discarded that key their message is silently undecryptable. Sharing the
    /// ring's retirement deadlines means the two halves of a certificate expire
    /// together instead of one outliving the other.
    pub fn ratchet_secrets(&self, now_unix: u64) -> Zeroizing<Vec<[u8; 32]>> {
        let st = self.read();
        let mut out = Vec::with_capacity(1 + st.retired.len());
        out.push(*veil_crypto::identity::derive_ratchet_x25519_sk(
            st.seed.as_array(),
        ));
        for r in &st.retired {
            if r.usable_until >= now_unix {
                out.push(*veil_crypto::identity::derive_ratchet_x25519_sk(
                    r.seed.as_array(),
                ));
            }
        }
        Zeroizing::new(out)
    }

    /// Every seed a correctly-sealed ciphertext could be addressed to, current
    /// first, then retired newest-first.
    ///
    /// The order matters for cost, not correctness: ML-KEM decapsulation never
    /// reports failure (implicit rejection returns a wrong shared secret), so a
    /// wrong candidate surfaces as an AEAD open failure and the caller moves to
    /// the next. Steady-state traffic hits the first candidate, and the extra
    /// attempts are only spent on a message that was going to fail anyway.
    ///
    /// The result is zeroized on drop, and preallocated so no reallocation
    /// leaves a copy of a seed behind in a freed buffer.
    pub fn decrypt_seeds(&self, now_unix: u64) -> Zeroizing<Vec<[u8; DK_SEED_BYTES]>> {
        let st = self.read();
        let mut out = Vec::with_capacity(1 + st.retired.len());
        out.push(*st.seed.as_array());
        for r in &st.retired {
            if r.usable_until >= now_unix {
                out.push(*r.seed.as_array());
            }
        }
        Zeroizing::new(out)
    }

    /// Install `(epoch, seed, ek)` as current and retire the outgoing seed for
    /// `overlap_secs`.
    ///
    /// Refuses rather than silently narrowing the window — see [`RotateRejected`].
    pub fn rotate(
        &self,
        now_unix: u64,
        epoch: u64,
        seed: [u8; DK_SEED_BYTES],
        ek: [u8; EK_BYTES],
        overlap_secs: u64,
    ) -> Result<(), RotateRejected> {
        if overlap_secs < MLKEM_SEED_MIN_OVERLAP_SECS {
            return Err(RotateRejected::OverlapTooShort {
                requested: overlap_secs,
                minimum: MLKEM_SEED_MIN_OVERLAP_SECS,
            });
        }
        let mut st = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if epoch <= st.epoch {
            return Err(RotateRejected::EpochNotAdvancing {
                requested: epoch,
                current: st.epoch,
            });
        }
        let outgoing = std::mem::replace(&mut st.seed, SensitiveBytesN::from_bytes(seed));
        st.epoch = epoch;
        st.ek = ek;
        st.retired.insert(
            0,
            RetiredSeed {
                seed: outgoing,
                usable_until: now_unix.saturating_add(overlap_secs),
            },
        );
        st.retired.retain(|r| r.usable_until >= now_unix);
        st.retired.truncate(MAX_RETIRED_SEEDS);
        Ok(())
    }

    /// Drop (and zeroize) retired seeds nothing can still be sealed to.
    ///
    /// [`decrypt_seeds`](Self::decrypt_seeds) already skips them, so this is
    /// about not holding expired key material in memory, which is the entire
    /// point of rotating.
    pub fn prune(&self, now_unix: u64) {
        let mut st = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        st.retired.retain(|r| r.usable_until >= now_unix);
    }

    /// Retired seeds currently held, expired ones included.
    pub fn retired_len(&self) -> usize {
        self.read().retired.len()
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, RingState> {
        self.state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl std::fmt::Debug for MlKemSeedRing {
    /// Deliberately opaque: the seed must never reach a log line.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let st = self.read();
        f.debug_struct("MlKemSeedRing")
            .field("epoch", &st.epoch)
            .field("retired", &st.retired.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OVERLAP: u64 = MLKEM_SEED_MIN_OVERLAP_SECS;

    fn ring(seed_byte: u8) -> MlKemSeedRing {
        MlKemSeedRing::new(0, [seed_byte; DK_SEED_BYTES], [seed_byte; EK_BYTES])
    }

    #[test]
    fn fresh_ring_offers_only_the_current_seed() {
        let r = ring(0x11);
        let seeds = r.decrypt_seeds(1_000);
        assert_eq!(seeds.len(), 1);
        assert_eq!(seeds[0], [0x11u8; DK_SEED_BYTES]);
        assert_eq!(r.epoch(), 0);
    }

    #[test]
    fn the_ratchet_key_belongs_to_the_current_seed() {
        // The whole reason the ratchet key is derived rather than stored: it
        // cannot disagree with the mailbox seed, because it is a function of
        // it. Publishing one epoch's encapsulation key beside another epoch's
        // ratchet key would make first contact fail silently.
        let r = ring(0x11);
        let want = veil_crypto::identity::derive_ratchet_x25519_sk(&r.current_seed());
        assert_eq!(*r.current_ratchet_sk(), *want);
        assert_eq!(
            r.current_ratchet_pk(),
            *x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*want)).as_bytes()
        );
        assert_ne!(r.current_ratchet_pk(), [0u8; 32]);
    }

    #[test]
    fn the_ratchet_key_rotates_with_the_seed_and_keeps_its_predecessor() {
        // A sender holding a week-old certificate derived the root key from
        // the ratchet key in it. Discarding that key the moment we rotate
        // would make their message undecryptable with no error anywhere — the
        // same black hole the seed overlap exists to prevent, which is why the
        // two share one retirement deadline instead of having two.
        let r = ring(0x11);
        let before_pk = r.current_ratchet_pk();
        let before_sk = *r.current_ratchet_sk();

        r.rotate(
            1_000,
            1,
            [0x22; DK_SEED_BYTES],
            [0x22; EK_BYTES],
            OVERLAP,
        )
        .expect("rotate");

        assert_ne!(r.current_ratchet_pk(), before_pk, "the key must turn over");

        let usable = r.ratchet_secrets(1_000);
        assert_eq!(usable.len(), 2, "current plus the one still in its window");
        assert_eq!(usable[0], *r.current_ratchet_sk());
        assert_eq!(usable[1], before_sk, "the predecessor must still be offered");

        // And it drops out exactly when the mailbox seed does.
        let past = 1_000 + OVERLAP + 1;
        assert_eq!(r.ratchet_secrets(past).len(), 1);
        assert_eq!(r.decrypt_seeds(past).len(), 1);
    }

    #[test]
    fn ratchet_secrets_track_decrypt_seeds_one_for_one() {
        // Stated as an invariant rather than left to inspection: any seed a
        // ciphertext could be addressed to has a ratchet secret a first
        // message could be addressed to, and vice versa.
        let r = ring(0x11);
        for (i, byte) in [0x22u8, 0x33, 0x44].into_iter().enumerate() {
            r.rotate(
                1_000,
                i as u64 + 1,
                [byte; DK_SEED_BYTES],
                [byte; EK_BYTES],
                OVERLAP,
            )
            .expect("rotate");
        }
        for now in [1_000, 1_000 + OVERLAP, 1_000 + OVERLAP + 1] {
            assert_eq!(
                r.ratchet_secrets(now).len(),
                r.decrypt_seeds(now).len(),
                "the two halves diverged at {now}"
            );
        }
    }

    #[test]
    fn rotate_swaps_ek_and_seed_together() {
        // The single-source-of-truth property: after a rotation the published EK
        // and the sealing seed are the NEW pair, never a mix of generations.
        let r = ring(0x11);
        r.rotate(1_000, 1, [0x22; DK_SEED_BYTES], [0x22; EK_BYTES], OVERLAP)
            .expect("advancing epoch with a full overlap");
        assert_eq!(r.current_ek(), [0x22u8; EK_BYTES]);
        assert_eq!(*r.current_seed(), [0x22u8; DK_SEED_BYTES]);
        assert_eq!(r.epoch(), 1);
    }

    #[test]
    fn retired_seed_still_decrypts_inside_the_window() {
        // Mail sealed to the old EK arrives after the rotation — the whole reason
        // the old seed is kept at all.
        let r = ring(0x11);
        r.rotate(1_000, 1, [0x22; DK_SEED_BYTES], [0x22; EK_BYTES], OVERLAP)
            .unwrap();
        let seeds = r.decrypt_seeds(1_000 + OVERLAP);
        assert_eq!(
            seeds.as_slice(),
            &[[0x22u8; DK_SEED_BYTES], [0x11u8; DK_SEED_BYTES]],
            "current first, then the retired predecessor"
        );
    }

    #[test]
    fn retired_seed_drops_out_after_the_window() {
        let r = ring(0x11);
        r.rotate(1_000, 1, [0x22; DK_SEED_BYTES], [0x22; EK_BYTES], OVERLAP)
            .unwrap();
        let seeds = r.decrypt_seeds(1_000 + OVERLAP + 1);
        assert_eq!(seeds.as_slice(), &[[0x22u8; DK_SEED_BYTES]]);
        // …and prune actually releases the memory, not just hides it.
        r.prune(1_000 + OVERLAP + 1);
        assert_eq!(r.retired_len(), 0);
    }

    #[test]
    fn overlap_shorter_than_a_mailbox_lifetime_is_refused() {
        // The live-path figure (1 h cache + 6 h republish) looks plausible and
        // would silently drop a week of store-and-forward mail. Refused, not
        // clamped: a caller that asked for it has a wrong model.
        let r = ring(0x11);
        let err = r
            .rotate(1_000, 1, [0x22; DK_SEED_BYTES], [0x22; EK_BYTES], 7 * 3600)
            .expect_err("must refuse a live-path-only overlap");
        assert_eq!(
            err,
            RotateRejected::OverlapTooShort {
                requested: 7 * 3600,
                minimum: MLKEM_SEED_MIN_OVERLAP_SECS,
            }
        );
        // And nothing moved.
        assert_eq!(r.epoch(), 0);
        assert_eq!(r.current_ek(), [0x11u8; EK_BYTES]);
    }

    #[test]
    fn overlap_covers_a_full_mailbox_retention() {
        // The behavioural half of the guard above: a blob deposited the instant
        // before a rotation, fetched on the last day the relay still holds it,
        // must still open.
        let r = ring(0x11);
        r.rotate(1_000, 1, [0x22; DK_SEED_BYTES], [0x22; EK_BYTES], OVERLAP)
            .unwrap();
        let seeds = r.decrypt_seeds(1_000 + MAILBOX_RETENTION_SECS);
        assert!(
            seeds.contains(&[0x11u8; DK_SEED_BYTES]),
            "a week-old blob must still find its seed"
        );
    }

    #[test]
    fn non_advancing_epoch_is_refused() {
        let r = ring(0x11);
        r.rotate(1_000, 1, [0x22; DK_SEED_BYTES], [0x22; EK_BYTES], OVERLAP)
            .unwrap();
        for epoch in [0u64, 1] {
            let err = r
                .rotate(
                    2_000,
                    epoch,
                    [0x33; DK_SEED_BYTES],
                    [0x33; EK_BYTES],
                    OVERLAP,
                )
                .expect_err("epoch must strictly advance");
            assert_eq!(
                err,
                RotateRejected::EpochNotAdvancing {
                    requested: epoch,
                    current: 1
                }
            );
        }
        assert_eq!(
            r.current_ek(),
            [0x22u8; EK_BYTES],
            "refusal changed nothing"
        );
    }

    #[test]
    fn retired_set_is_bounded_and_evicts_the_oldest() {
        // Only reachable by a caller rotating far faster than the overlap, which
        // `rotate` cannot itself prevent (the epoch is the caller's). The bound
        // keeps that from growing without limit; dropping the oldest keeps the
        // most recently published keys.
        let r = ring(0x00);
        for e in 1..=(MAX_RETIRED_SEEDS as u64 + 2) {
            r.rotate(
                1_000,
                e,
                [e as u8; DK_SEED_BYTES],
                [e as u8; EK_BYTES],
                OVERLAP,
            )
            .unwrap();
        }
        assert_eq!(r.retired_len(), MAX_RETIRED_SEEDS);
        let seeds = r.decrypt_seeds(1_000);
        assert_eq!(seeds.len(), MAX_RETIRED_SEEDS + 1);
        assert!(
            !seeds.contains(&[0x00u8; DK_SEED_BYTES]),
            "the oldest seed is the one evicted"
        );
    }

    #[test]
    fn ring_stores_the_seed_in_mlockable_storage() {
        // Inherited from the dispatcher's Phase 6 slice 6g guard, which asserted
        // this when the seed was a field there. A plain `[u8; 64]` would compile
        // everywhere else and silently drop the mlock-when-possible guarantee,
        // so the type is pinned where the bytes now live.
        let r = ring(0x11);
        let st = r.read();
        let _: &SensitiveBytesN<DK_SEED_BYTES> = &st.seed;
        assert_eq!(st.seed.as_array().len(), DK_SEED_BYTES);
    }

    #[test]
    fn debug_never_prints_key_material() {
        // The seed is 64 bytes of secret sitting in a struct that will end up in
        // some diagnostic `{:?}` eventually. Make that safe by construction.
        let r = ring(0xAB);
        let rendered = format!("{r:?}");
        assert!(!rendered.contains("ab"), "{rendered}");
        assert!(!rendered.contains("171"), "{rendered}");
        assert!(rendered.contains("epoch"));
    }
}
