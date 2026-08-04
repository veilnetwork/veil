//! Hybrid Double Ratchet + PQXDH for one-to-one messaging.
//!
//! # Why this crate exists
//!
//! Until now one-to-one messaging had **no key agreement at all**: every
//! message was an independent ML-KEM encapsulation to the recipient's
//! long-lived published key (`veil-e2e::encrypt`). Nothing was negotiated, so
//! there was no forward secrecy — one leaked decapsulation seed opened every
//! message ever sealed to it inside the rotation window — and no sender
//! authentication on the store-and-forward path.
//!
//! This crate supplies the missing layer:
//!
//! * [`pqxdh`] — asynchronous key agreement against **already-published**
//!   material, modelled on Signal's PQXDH. It needs nothing online from the
//!   recipient.
//! * [`RatchetSession`] — a hybrid Double Ratchet whose asymmetric step mixes
//!   an X25519 Diffie-Hellman **and** an ML-KEM-768 encapsulation on every
//!   epoch. Message keys are single-use and dropped after use.
//!
//! # The six requirements, and where each is met
//!
//! | Requirement | Met by |
//! |---|---|
//! | Forward secrecy | [`RatchetSession`]: chain keys advance one-way, message keys are consumed, the asymmetric step re-keys the root from fresh secrets both sides discard. |
//! | Deniability | **Nothing in the transcript is signed.** Every authenticator is a symmetric AEAD tag under a key both parties hold, so either party (and anyone they hand the key to) can forge a complete transcript. See [`deniability`](self#deniability). |
//! | Post-quantum | The ML-KEM-768 leg is **mandatory** in every asymmetric step, not optional: a header without an encapsulation key is rejected ([`RatchetError::PqDowngrade`]). |
//! | Asynchrony | [`pqxdh::initiate`] only reads the recipient's published, already-signed certificate. The recipient may be offline for the entire exchange. |
//! | No new long-lived identifiers | The initiator authenticates with an X25519 key **derived from the existing device secret** and published as a new field of the **existing** signed certificate. No new record, no new DHT slot, no new name. |
//! | Format may break | There is no compatibility shim; the wire tags are `v1` from the start. |
//!
//! # Choice of implementation
//!
//! No crates.io implementation could be taken as a dependency. The full
//! survey is in the task report; the short version:
//!
//! * `pq-ratchet` 0.2.0 is the only published crate with an ML-KEM leg in the
//!   asymmetric step, but its repository 404s, it has 18 downloads, one
//!   unaudited author, and GPL-3.0-only (which `deny.toml` refuses a second
//!   time by explicit written policy). Two defects were found by reading it:
//!   it commits ratchet state **before** the caller verifies the AEAD, so one
//!   injected header permanently destroys a conversation; and it treats the
//!   post-quantum leg as optional, deriving from 32 zero bytes when a header
//!   omits it.
//! * Signal's own SPQR (`spqr-syft`) is real, formally-verified code, but it
//!   is only the post-quantum half of a Triple Ratchet, and its `build.rs`
//!   runs `prost_build::compile_protos`, which needs `protoc` on every build
//!   host — a non-starter for a tree that cross-builds five targets.
//! * Every other candidate is X25519-only, group-oriented, or a pre-release
//!   pulling a second generation of RustCrypto into the tree.
//!
//! So the *design* is taken ready-made and the *code* is written here: the
//! symmetric and Diffie-Hellman ratchets follow Signal's published Double
//! Ratchet specification section for section (including its
//! skipped-message-key handling), and the post-quantum leg follows the same
//! epoch-bound KEM pattern that `pq-ratchet` implements — with both of its
//! defects designed out. Nothing about the construction is invented here.
//!
//! # Deniability
//!
//! An authenticator is *deniable* when the party it convinces could have
//! produced it themselves. Concretely, in everything this crate puts on the
//! wire:
//!
//! * The PQXDH prologue carries two X25519 public keys and one ML-KEM
//!   ciphertext. No signature. The root key is
//!   `DH(IK_a, IK_b) ‖ DH(EK_a, IK_b) ‖ Decaps(ct)`, and the responder holds
//!   `ik_b` and the decapsulation seed — so the responder can compute all
//!   three legs for **any** `IK_a`/`EK_a` they care to invent, and thus mint a
//!   complete "message from A" without A's participation.
//! * Every ratchet frame is authenticated by a ChaCha20-Poly1305 tag under a
//!   message key derived from that same root. Symmetric. Both parties can
//!   produce it; neither can attribute it.
//!
//! The device X25519 key *is* published inside a signed certificate — but that
//! signature attests "this key belongs to this device", which was already
//! public before this crate existed. It says nothing about who spoke to whom.
//! This is the same position Signal occupies, and it is pinned by
//! [`session::tests::transcript_carries_no_signature`] and
//! [`pqxdh::tests::responder_can_forge_a_transcript_from_the_initiator`].
//!
//! # What this crate does not do
//!
//! It holds no storage. [`RatchetSession::export_state`] /
//! [`RatchetSession::import_state`] hand the whole session out as an opaque,
//! canonical blob; persisting it (encrypted, durably, per conversation) is the
//! caller's job. In this project that store is xVeil's hidden volume.

pub mod pqxdh;

mod kdf;
mod pq;
mod ratchet;
mod session;

pub use pq::{ML_KEM_768_CT_LEN, ML_KEM_768_EK_LEN, ML_KEM_768_SEED_LEN};
pub use pqxdh::{InitialMessage, PQXDH_MAGIC, PROLOGUE_LEN as PQXDH_PROLOGUE_LEN};
pub use ratchet::{MAX_SKIP, MAX_SKIP_TOTAL};
pub use session::{RATCHET_FRAME_MAGIC, RATCHET_STATE_MAGIC, RatchetSession};

use zeroize::Zeroizing;

/// Length of a root key, chain key, and message key.
pub const KEY_LEN: usize = 32;

/// Everything that can go wrong in key agreement or in the ratchet.
///
/// Deliberately coarse on the receive path: a peer must not be able to tell a
/// wrong key from a wrong counter from a malformed frame by watching which
/// error comes back, so the caller should surface all of these identically.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RatchetError {
    /// The frame is not a ratchet frame, is truncated, or has trailing bytes.
    #[error("malformed ratchet frame: {0}")]
    MalformedFrame(&'static str),

    /// Persisted session state did not decode.
    #[error("malformed ratchet state: {0}")]
    MalformedState(&'static str),

    /// An ML-KEM encapsulation key on the wire is not a valid ML-KEM-768 key.
    #[error("invalid ML-KEM-768 encapsulation key")]
    InvalidPqKey,

    /// A stored ML-KEM decapsulation seed is not 64 bytes.
    #[error("invalid ML-KEM-768 decapsulation seed")]
    InvalidPqSeed,

    /// The peer's X25519 public key is a low-order point, so the Diffie-Hellman
    /// output is a constant the peer chose. Continuing would derive the root
    /// key from a value the attacker knows.
    #[error("non-contributory X25519: peer public key is a low-order point")]
    NonContributory,

    /// An asymmetric ratchet step arrived without its post-quantum leg.
    ///
    /// This is a hard error, never a downgrade: the post-quantum contribution
    /// is a requirement of this protocol, so a header that omits it is treated
    /// exactly like a forged one.
    #[error("post-quantum downgrade: asymmetric step is missing its ML-KEM leg")]
    PqDowngrade,

    /// The AEAD tag did not verify. The session state is unchanged.
    #[error("authentication failed")]
    AuthFailed,

    /// The peer asked us to skip more message keys than the cache allows.
    #[error("too many skipped messages ({0})")]
    TooManySkipped(usize),

    /// The message key is gone: either the message was already decrypted, or
    /// it is older than everything still in the skipped-key cache.
    #[error("message key unavailable (replay, or too far behind)")]
    MessageKeyUnavailable,

    /// We have no sending chain yet — the responder must decrypt one message
    /// before it can encrypt.
    #[error("no sending chain established yet")]
    NoSendingChain,
}

/// Source of randomness for key generation.
///
/// Deliberately not `rand_core::RngCore`: the two halves of this crate sit on
/// opposite sides of a `rand_core` major version (`x25519-dalek` is on 0.6,
/// `ml-kem` is on 0.10), and everything here consumes raw bytes anyway. A
/// one-method trait lets both halves share one source and lets the tests pin
/// known-answer vectors against a deterministic one.
pub trait RatchetRng {
    /// Fill `dest` with cryptographically secure random bytes.
    fn fill_bytes(&mut self, dest: &mut [u8]);
}

/// The operating-system random source.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsRatchetRng;

impl RatchetRng for OsRatchetRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, dest);
    }
}

impl<T: RatchetRng + ?Sized> RatchetRng for &mut T {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        (**self).fill_bytes(dest);
    }
}

pub(crate) fn random_array<const N: usize>(rng: &mut impl RatchetRng) -> Zeroizing<[u8; N]> {
    let mut out = Zeroizing::new([0u8; N]);
    rng.fill_bytes(out.as_mut());
    out
}

// ── Test-only deterministic randomness ───────────────────────────────────────

/// A deterministic SHA-256 counter stream, for tests only.
///
/// Every test that needs reproducible keys builds one of these. It is *not*
/// exported: production callers get [`OsRatchetRng`] and nothing else, so there
/// is no path by which a deterministic stream reaches a real session.
#[cfg(test)]
#[derive(Debug, Clone)]
pub(crate) struct TestRng {
    seed: [u8; 32],
    counter: u64,
}

#[cfg(test)]
impl TestRng {
    pub(crate) fn new(label: u8) -> Self {
        Self {
            seed: [label; 32],
            counter: 0,
        }
    }
}

#[cfg(test)]
impl RatchetRng for TestRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        use sha2::{Digest, Sha256};
        for chunk in dest.chunks_mut(32) {
            let mut h = Sha256::new();
            h.update(b"veil.ratchet.testrng");
            h.update(self.seed);
            h.update(self.counter.to_be_bytes());
            self.counter += 1;
            let block = h.finalize();
            chunk.copy_from_slice(&block[..chunk.len()]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rng_is_deterministic_and_not_constant() {
        let mut a = TestRng::new(7);
        let mut b = TestRng::new(7);
        let mut c = TestRng::new(8);
        let (mut xa, mut xb, mut xc) = ([0u8; 96], [0u8; 96], [0u8; 96]);
        a.fill_bytes(&mut xa);
        b.fill_bytes(&mut xb);
        c.fill_bytes(&mut xc);
        assert_eq!(xa, xb, "same label must reproduce the same stream");
        assert_ne!(xa, xc, "different labels must diverge");
        assert_ne!(xa[..32], xa[32..64], "successive blocks must differ");
    }

    #[test]
    fn os_rng_produces_varying_bytes() {
        let mut rng = OsRatchetRng;
        let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
        rng.fill_bytes(&mut a);
        rng.fill_bytes(&mut b);
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 32]);
    }
}
