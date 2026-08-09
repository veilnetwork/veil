//! The Double Ratchet state machine, with a mandatory post-quantum leg.
//!
//! Structure follows Signal's published Double Ratchet specification: a root
//! chain re-keyed by each asymmetric step, two symmetric chains hanging off
//! it, and a bounded cache of message keys for messages that arrive late. What
//! is added on top is that every asymmetric step mixes an ML-KEM-768 shared
//! secret alongside the X25519 one, and that the post-quantum contribution is
//! **required** rather than opportunistic.
//!
//! This module derives keys and nothing else. It never sees a plaintext and
//! never commits: [`crate::session`] owns the AEAD and only writes a step back
//! into the live session once the tag has verified.

use std::collections::BTreeMap;

use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::kdf::{kdf_ck, kdf_rk, zeroize_opt};
use crate::pq::{ML_KEM_768_CT_LEN, ML_KEM_768_EK_LEN, PqEpoch, encapsulate_to};
use crate::{KEY_LEN, RatchetError, RatchetRng, random_array};

/// How many message keys one arriving message may cause us to skip.
///
/// Signal's recommended bound. A peer that claims a jump larger than this is
/// either broken or trying to make us burn CPU deriving keys.
pub const MAX_SKIP: usize = 1_000;

/// How many skipped message keys may be held across all epochs at once.
///
/// Without this, a peer could step through many epochs, each leaving a
/// near-`MAX_SKIP` batch behind, and grow the cache without bound.
pub const MAX_SKIP_TOTAL: usize = 2_000;

/// The per-message header, before it is serialized.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Header {
    /// Sender's current X25519 ratchet public key.
    pub(crate) dh_pk: [u8; 32],
    /// Length of the sender's previous sending chain, so the receiver knows
    /// how many keys to bank before switching epochs.
    pub(crate) pn: u32,
    /// Index of this message within the sender's current sending chain.
    pub(crate) n: u32,
    /// Sender's current ML-KEM-768 encapsulation key.
    pub(crate) pq_ek: Option<[u8; ML_KEM_768_EK_LEN]>,
    /// Sender's answer to the encapsulation key we announced.
    pub(crate) pq_ct: Option<[u8; ML_KEM_768_CT_LEN]>,
}

/// One end of a conversation.
#[derive(Clone)]
pub(crate) struct RatchetCore {
    dh_sk: StaticSecret,
    dh_pk: [u8; 32],
    dh_pk_remote: Option<[u8; 32]>,

    rk: [u8; KEY_LEN],
    cks: Option<[u8; KEY_LEN]>,
    ckr: Option<[u8; KEY_LEN]>,

    ns: u32,
    nr: u32,
    pn: u32,

    /// `(peer ratchet key, index) → message key`, for messages that arrived
    /// out of order. A `BTreeMap` rather than a `HashMap` so that exporting
    /// the session produces the same bytes every time — a hash map's iteration
    /// order would make the blob non-canonical and every diff spurious.
    skipped: BTreeMap<([u8; 32], u32), Zeroizing<[u8; KEY_LEN]>>,

    pq: PqEpoch,

    /// Whether we have ever emitted a header. Once we have, the peer has seen
    /// an encapsulation key from us, so every asymmetric step they take must
    /// answer it. Before that, they have nothing to answer.
    sent_any: bool,
}

impl Drop for RatchetCore {
    fn drop(&mut self) {
        self.rk.zeroize();
        zeroize_opt(&mut self.cks);
        zeroize_opt(&mut self.ckr);
        for v in self.skipped.values_mut() {
            v.zeroize();
        }
    }
}

impl core::fmt::Debug for RatchetCore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RatchetCore")
            .field("ns", &self.ns)
            .field("nr", &self.nr)
            .field("pn", &self.pn)
            .field("skipped", &self.skipped.len())
            .field("has_sending_chain", &self.cks.is_some())
            .field("has_receiving_chain", &self.ckr.is_some())
            .finish_non_exhaustive()
    }
}

// ── Construction ─────────────────────────────────────────────────────────────

impl RatchetCore {
    /// The party that speaks first.
    ///
    /// Takes one asymmetric step immediately against the ratchet key the peer
    /// published, so it can encrypt without waiting. That first step has no
    /// ML-KEM leg of its own — the peer has announced no encapsulation key we
    /// could answer yet — which is safe precisely because `root` is the PQXDH
    /// output and already contains an ML-KEM shared secret.
    pub(crate) fn initiator(
        root: &[u8; KEY_LEN],
        peer_dh_pk: &[u8; 32],
        rng: &mut impl RatchetRng,
    ) -> Result<Self, RatchetError> {
        let dh_sk = StaticSecret::from(*random_array::<32>(rng));
        let dh_pk = *PublicKey::from(&dh_sk).as_bytes();

        let shared = dh_sk.diffie_hellman(&PublicKey::from(*peer_dh_pk));
        if !shared.was_contributory() {
            return Err(RatchetError::NonContributory);
        }
        let (rk, cks) = kdf_rk(root, shared.as_bytes(), None);

        Ok(Self {
            dh_sk,
            dh_pk,
            dh_pk_remote: Some(*peer_dh_pk),
            rk,
            cks: Some(cks),
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped: BTreeMap::new(),
            pq: PqEpoch::new(rng),
            sent_any: false,
        })
    }

    /// The party that is addressed first.
    ///
    /// `our_dh_sk` is the secret half of the ratchet key we published — here,
    /// the rotating device X25519 key carried in our signed certificate. No
    /// step is taken yet; both chains come into being when the first message
    /// arrives.
    pub(crate) fn responder(
        root: &[u8; KEY_LEN],
        our_dh_sk: [u8; 32],
        rng: &mut impl RatchetRng,
    ) -> Self {
        let dh_sk = StaticSecret::from(our_dh_sk);
        let dh_pk = *PublicKey::from(&dh_sk).as_bytes();
        Self {
            dh_sk,
            dh_pk,
            dh_pk_remote: None,
            rk: *root,
            cks: None,
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped: BTreeMap::new(),
            pq: PqEpoch::new(rng),
            sent_any: false,
        }
    }
}

// ── Stepping ─────────────────────────────────────────────────────────────────

impl RatchetCore {
    /// Advance the sending chain by one and hand back the header and key.
    pub(crate) fn send_step(&mut self) -> Result<(Header, Zeroizing<[u8; KEY_LEN]>), RatchetError> {
        let cks = self.cks.as_mut().ok_or(RatchetError::NoSendingChain)?;
        let (next, mk) = kdf_ck(cks);
        *cks = next;

        let n = self.ns;
        self.ns = self.ns.saturating_add(1);
        self.sent_any = true;

        Ok((
            Header {
                dh_pk: self.dh_pk,
                pn: self.pn,
                n,
                pq_ek: Some(*self.pq.ek()),
                pq_ct: self.pq.pending_ct().copied(),
            },
            mk,
        ))
    }

    /// Resolve the message key for an arriving header.
    ///
    /// Mutates. The caller runs this against a scratch copy and keeps the
    /// result only if the AEAD tag then verifies — see [`crate::session`].
    pub(crate) fn recv_step(
        &mut self,
        header: &Header,
        rng: &mut impl RatchetRng,
    ) -> Result<Zeroizing<[u8; KEY_LEN]>, RatchetError> {
        // Banked from an earlier out-of-order scan.
        if let Some(mk) = self.skipped.remove(&(header.dh_pk, header.n)) {
            return Ok(mk);
        }

        let is_new_epoch = match self.dh_pk_remote {
            Some(pk) => bool::from(pk.ct_ne(&header.dh_pk)),
            None => true,
        };

        if is_new_epoch {
            // Bank whatever is left of the chain the peer just abandoned.
            if self.ckr.is_some() {
                self.skip_message_keys(header.pn)?;
            }
            self.asymmetric_step(header, rng)?;
        }

        // Within an epoch, an index we have already passed is a replay: the
        // key was consumed, and if it had been skipped it would have been
        // found in the cache above.
        if header.n < self.nr {
            return Err(RatchetError::MessageKeyUnavailable);
        }
        self.skip_message_keys(header.n)?;

        let ckr = self
            .ckr
            .as_mut()
            .ok_or(RatchetError::MessageKeyUnavailable)?;
        let (next, mk) = kdf_ck(ckr);
        *ckr = next;
        self.nr = self.nr.saturating_add(1);
        Ok(mk)
    }

    /// Re-key the root from a fresh X25519 exchange and a fresh ML-KEM
    /// exchange, then hang a new receiving and a new sending chain off it.
    fn asymmetric_step(
        &mut self,
        header: &Header,
        rng: &mut impl RatchetRng,
    ) -> Result<(), RatchetError> {
        // The post-quantum leg is a requirement, not an optimisation. A header
        // that omits the encapsulation key would leave the outgoing chain with
        // no ML-KEM contribution at all, which is exactly the downgrade this
        // protocol exists to rule out.
        let peer_ek = header.pq_ek.ok_or(RatchetError::PqDowngrade)?;

        let pq_recv = match header.pq_ct {
            Some(ct) => Some(self.pq.decapsulate(&ct)),
            None => {
                // Legal exactly once: the peer's first step, before they could
                // have seen an encapsulation key from us. After we have sent
                // anything, a missing answer is a downgrade attempt.
                if self.sent_any {
                    return Err(RatchetError::PqDowngrade);
                }
                None
            }
        };

        let (pq_send, our_ct) = encapsulate_to(&peer_ek, rng)?;

        let peer_pk = PublicKey::from(header.dh_pk);
        let dh_recv = self.dh_sk.diffie_hellman(&peer_pk);
        if !dh_recv.was_contributory() {
            return Err(RatchetError::NonContributory);
        }

        let new_dh_sk = StaticSecret::from(*random_array::<32>(rng));
        let new_dh_pk = *PublicKey::from(&new_dh_sk).as_bytes();
        let dh_send = new_dh_sk.diffie_hellman(&peer_pk);
        if !dh_send.was_contributory() {
            return Err(RatchetError::NonContributory);
        }

        // Everything fallible is done; from here the step cannot half-apply.
        let (rk1, ckr) = kdf_rk(&self.rk, dh_recv.as_bytes(), pq_recv.as_ref());
        let (rk2, cks) = kdf_rk(&rk1, dh_send.as_bytes(), Some(&pq_send));

        let mut new_pq = PqEpoch::new(rng);
        new_pq.set_pending_ct(our_ct);

        self.rk.zeroize();
        zeroize_opt(&mut self.ckr);
        zeroize_opt(&mut self.cks);

        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        // Age the bank by epoch. A skipped key is filed under the remote public
        // key of the epoch that would open it, and it only ever left this map
        // when its message arrived — so keys for messages that never came sat
        // here until MAX_SKIP_TOTAL. That is not a memory problem, it is a DISK
        // one: the host persists the whole session on every advance into a
        // container that may never reuse the slots it leaves behind. Measured
        // on a real profile: 23,421 bytes of stored state, 324 banked keys
        // spread over 42 epochs, and NONE in the current one — about 64 MB a
        // day rewritten for keys nothing could still use.
        //
        // Two epochs are kept: the one just ending and the one starting. A
        // step happens when the conversation changes direction, so that is the
        // window in which a straggler from the old chain can still turn up;
        // beyond it the peer has ratcheted twice and anything that old would
        // have to be re-sent anyway.
        let ending = self.dh_pk_remote;
        self.skipped
            .retain(|(pk, _), _| Some(*pk) == ending || *pk == header.dh_pk);
        self.dh_pk_remote = Some(header.dh_pk);
        self.rk = rk2;
        self.ckr = Some(ckr);
        self.cks = Some(cks);
        self.dh_sk = new_dh_sk;
        self.dh_pk = new_dh_pk;
        self.pq = new_pq;
        Ok(())
    }

    /// Derive and bank the message keys for indices `nr .. until`.
    fn skip_message_keys(&mut self, until: u32) -> Result<(), RatchetError> {
        if until <= self.nr {
            return Ok(());
        }
        let to_skip = (until - self.nr) as usize;
        if to_skip > MAX_SKIP {
            return Err(RatchetError::TooManySkipped(to_skip));
        }
        if self.skipped.len() + to_skip > MAX_SKIP_TOTAL {
            return Err(RatchetError::TooManySkipped(self.skipped.len() + to_skip));
        }

        let Some(ckr) = self.ckr.as_mut() else {
            return Ok(());
        };
        let remote = self
            .dh_pk_remote
            .expect("a receiving chain only ever exists alongside a peer ratchet key");
        for i in self.nr..until {
            let (next, mk) = kdf_ck(ckr);
            *ckr = next;
            self.skipped.insert((remote, i), mk);
        }
        self.nr = until;
        Ok(())
    }
}

// ── Persistence support ──────────────────────────────────────────────────────

impl RatchetCore {
    pub(crate) fn parts(&self) -> CoreParts<'_> {
        CoreParts {
            dh_sk: self.dh_sk.to_bytes(),
            dh_pk_remote: self.dh_pk_remote,
            rk: self.rk,
            cks: self.cks,
            ckr: self.ckr,
            ns: self.ns,
            nr: self.nr,
            pn: self.pn,
            sent_any: self.sent_any,
            skipped: &self.skipped,
            pq_seed: *self.pq.seed(),
            pending_ct: self.pq.pending_ct().copied(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_parts(
        dh_sk: [u8; 32],
        dh_pk_remote: Option<[u8; 32]>,
        rk: [u8; KEY_LEN],
        cks: Option<[u8; KEY_LEN]>,
        ckr: Option<[u8; KEY_LEN]>,
        ns: u32,
        nr: u32,
        pn: u32,
        sent_any: bool,
        skipped: BTreeMap<([u8; 32], u32), Zeroizing<[u8; KEY_LEN]>>,
        pq_seed: [u8; crate::pq::ML_KEM_768_SEED_LEN],
        pending_ct: Option<[u8; ML_KEM_768_CT_LEN]>,
    ) -> Self {
        let sk = StaticSecret::from(dh_sk);
        let dh_pk = *PublicKey::from(&sk).as_bytes();
        Self {
            dh_sk: sk,
            dh_pk,
            dh_pk_remote,
            rk,
            cks,
            ckr,
            ns,
            nr,
            pn,
            skipped,
            pq: PqEpoch::restore(&pq_seed, pending_ct),
            sent_any,
        }
    }

    /// How many skipped message keys this session is banking.
    ///
    /// A COUNT, never the keys: the host needs it because the session is
    /// persisted whole on every advance, and the bank is the part that can
    /// grow (bounded by [`MAX_SKIP_TOTAL`]). Measured on a real profile, one
    /// conversation's stored state reached ~23 KB and is rewritten in full
    /// every time the conversation moves, into a container that may never
    /// reuse the slots it leaves behind — so what the size is MADE of decides
    /// where the cut goes.
    #[must_use]
    pub fn skipped_len(&self) -> usize {
        self.skipped.len()
    }

    /// How many distinct DH epochs the bank spans, and how many of its keys
    /// belong to the CURRENT one.
    ///
    /// Which decides whether the bank can be aged at all. Keys are filed under
    /// the remote public key of the epoch that would open them, so a bank
    /// spread over many old epochs is mostly keys for messages that stopped
    /// being reachable long ago — and a bank concentrated in the current epoch
    /// is not, in which case epoch-ageing would cost decryptability and buy
    /// nothing. Counts only; no key material leaves.
    #[must_use]
    pub fn skipped_epochs(&self) -> (usize, usize) {
        let epochs: std::collections::BTreeSet<[u8; 32]> =
            self.skipped.keys().map(|(pk, _)| *pk).collect();
        let current = self.dh_pk_remote.map_or(0, |cur| {
            self.skipped.keys().filter(|(pk, _)| *pk == cur).count()
        });
        (epochs.len(), current)
    }

    #[cfg(test)]
    pub(crate) fn pq_ek(&self) -> &[u8; ML_KEM_768_EK_LEN] {
        self.pq.ek()
    }

    #[cfg(test)]
    pub(crate) fn pq_seed(&self) -> &[u8; crate::pq::ML_KEM_768_SEED_LEN] {
        self.pq.seed()
    }

    #[cfg(test)]
    pub(crate) fn dh_pk(&self) -> [u8; 32] {
        self.dh_pk
    }
}

/// A borrowed view of everything a session needs to serialize.
pub(crate) struct CoreParts<'a> {
    pub(crate) dh_sk: [u8; 32],
    pub(crate) dh_pk_remote: Option<[u8; 32]>,
    pub(crate) rk: [u8; KEY_LEN],
    pub(crate) cks: Option<[u8; KEY_LEN]>,
    pub(crate) ckr: Option<[u8; KEY_LEN]>,
    pub(crate) ns: u32,
    pub(crate) nr: u32,
    pub(crate) pn: u32,
    pub(crate) sent_any: bool,
    pub(crate) skipped: &'a BTreeMap<([u8; 32], u32), Zeroizing<[u8; KEY_LEN]>>,
    pub(crate) pq_seed: [u8; crate::pq::ML_KEM_768_SEED_LEN],
    pub(crate) pending_ct: Option<[u8; ML_KEM_768_CT_LEN]>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TestRng;

    /// Wire two cores together the way PQXDH does, without the key agreement.
    fn pair() -> (RatchetCore, RatchetCore, TestRng, TestRng) {
        let root = [0x42u8; KEY_LEN];
        let mut arng = TestRng::new(0xA1);
        let mut brng = TestRng::new(0xB1);
        let bob_sk = *random_array::<32>(&mut brng);
        let bob_pk = *PublicKey::from(&StaticSecret::from(bob_sk)).as_bytes();

        let alice = RatchetCore::initiator(&root, &bob_pk, &mut arng).expect("contributory");
        let bob = RatchetCore::responder(&root, bob_sk, &mut brng);
        (alice, bob, arng, brng)
    }

    #[test]
    fn first_message_agrees() {
        let (mut alice, mut bob, _ar, mut br) = pair();
        let (h, mk_a) = alice.send_step().expect("sending chain exists");
        let mk_b = bob.recv_step(&h, &mut br).expect("decrypts");
        assert_eq!(*mk_a, *mk_b);
    }

    #[test]
    fn responder_cannot_send_before_receiving() {
        let (_alice, mut bob, _ar, _br) = pair();
        assert_eq!(
            bob.send_step().unwrap_err(),
            RatchetError::NoSendingChain,
            "the responder has no sending chain until the first message lands"
        );
    }

    #[test]
    fn alternating_conversation_agrees_for_many_turns() {
        let (mut alice, mut bob, mut ar, mut br) = pair();
        for turn in 0..12u32 {
            let (h, mk_a) = alice.send_step().expect("chain");
            assert_eq!(
                *mk_a,
                *bob.recv_step(&h, &mut br).expect("a→b"),
                "turn {turn}"
            );
            let (h, mk_b) = bob.send_step().expect("chain");
            assert_eq!(
                *mk_b,
                *alice.recv_step(&h, &mut ar).expect("b→a"),
                "turn {turn}"
            );
        }
    }

    #[test]
    fn every_asymmetric_step_carries_a_post_quantum_leg() {
        let (mut alice, mut bob, mut ar, mut br) = pair();
        let (h1, _) = alice.send_step().expect("chain");
        assert!(h1.pq_ek.is_some(), "initiator must announce a key");
        assert!(
            h1.pq_ct.is_none(),
            "initiator has nothing to answer on its first message"
        );
        bob.recv_step(&h1, &mut br).expect("a→b");

        let (h2, _) = bob.send_step().expect("chain");
        assert!(h2.pq_ek.is_some());
        assert!(
            h2.pq_ct.is_some(),
            "the responder must answer the key it just saw"
        );
        alice.recv_step(&h2, &mut ar).expect("b→a");

        let (h3, _) = alice.send_step().expect("chain");
        assert!(h3.pq_ek.is_some() && h3.pq_ct.is_some());
    }

    #[test]
    fn a_step_without_an_encapsulation_key_is_refused() {
        let (mut alice, mut bob, _ar, mut br) = pair();
        let (mut h, _) = alice.send_step().expect("chain");
        h.pq_ek = None;
        assert_eq!(
            bob.recv_step(&h, &mut br).unwrap_err(),
            RatchetError::PqDowngrade
        );
    }

    #[test]
    fn a_step_that_drops_the_answer_after_we_have_spoken_is_refused() {
        let (mut alice, mut bob, mut ar, mut br) = pair();
        let (h1, _) = alice.send_step().expect("chain");
        bob.recv_step(&h1, &mut br).expect("a→b");

        let (mut h2, _) = bob.send_step().expect("chain");
        h2.pq_ct = None;
        assert_eq!(
            alice.recv_step(&h2, &mut ar).unwrap_err(),
            RatchetError::PqDowngrade,
            "once we have announced a key, every step must answer it"
        );
    }

    #[test]
    fn forward_secrecy_a_later_key_does_not_open_an_earlier_message() {
        let (mut alice, mut bob, _ar, mut br) = pair();
        let (h1, mk1) = alice.send_step().expect("chain");
        let (h2, mk2) = alice.send_step().expect("chain");
        assert_ne!(*mk1, *mk2);

        bob.recv_step(&h1, &mut br).expect("first");
        bob.recv_step(&h2, &mut br).expect("second");

        // Positive statement of forward secrecy: whatever state Bob holds now,
        // it cannot reproduce the first message's key.
        let mut leaked = bob.clone();
        let (h3, _) = alice.send_step().expect("chain");
        let mk3 = leaked.recv_step(&h3, &mut br).expect("third");
        assert_ne!(*mk3, *mk1);
        assert_ne!(*mk3, *mk2);
        assert_eq!(
            leaked.recv_step(&h1, &mut br).unwrap_err(),
            RatchetError::MessageKeyUnavailable,
            "the first message key is gone from the receiving state"
        );
    }

    #[test]
    fn out_of_order_within_an_epoch_is_handled() {
        let (mut alice, mut bob, _ar, mut br) = pair();
        let msgs: Vec<_> = (0..5).map(|_| alice.send_step().expect("chain")).collect();

        // Deliver 4, 0, 2, 1, 3.
        for idx in [4usize, 0, 2, 1, 3] {
            let (h, mk) = &msgs[idx];
            assert_eq!(
                *bob.recv_step(h, &mut br).expect("out of order"),
                **mk,
                "index {idx}"
            );
        }
        assert_eq!(bob.skipped_len(), 0, "every banked key must be consumed");
    }

    #[test]
    fn a_lost_message_does_not_stall_the_chain() {
        let (mut alice, mut bob, _ar, mut br) = pair();
        let msgs: Vec<_> = (0..4).map(|_| alice.send_step().expect("chain")).collect();

        // Message 1 never arrives.
        for idx in [0usize, 2, 3] {
            let (h, mk) = &msgs[idx];
            assert_eq!(*bob.recv_step(h, &mut br).expect("gap"), **mk);
        }
        assert_eq!(bob.skipped_len(), 1, "exactly the lost key stays banked");
    }

    #[test]
    fn keys_survive_across_an_epoch_boundary() {
        let (mut alice, mut bob, mut ar, mut br) = pair();
        // Alice sends three; only the first arrives.
        let a = [
            alice.send_step().expect("chain"),
            alice.send_step().expect("chain"),
            alice.send_step().expect("chain"),
        ];
        bob.recv_step(&a[0].0, &mut br).expect("first");

        // Bob replies, turning the epoch, and Alice replies again.
        let (hb, _) = bob.send_step().expect("chain");
        alice.recv_step(&hb, &mut ar).expect("b→a");
        let (h_new, mk_new) = alice.send_step().expect("chain");

        // The stragglers from the old epoch still open.
        assert_eq!(
            *bob.recv_step(&a[2].0, &mut br).expect("straggler"),
            *a[2].1
        );
        assert_eq!(
            *bob.recv_step(&a[1].0, &mut br).expect("straggler"),
            *a[1].1
        );
        // And so does the new epoch.
        assert_eq!(*bob.recv_step(&h_new, &mut br).expect("new epoch"), *mk_new);
    }

    #[test]
    fn a_replayed_message_is_refused() {
        let (mut alice, mut bob, _ar, mut br) = pair();
        let (h, _) = alice.send_step().expect("chain");
        bob.recv_step(&h, &mut br).expect("first delivery");
        assert_eq!(
            bob.recv_step(&h, &mut br).unwrap_err(),
            RatchetError::MessageKeyUnavailable,
            "a message key is consumed exactly once"
        );
    }

    #[test]
    fn an_absurd_skip_claim_is_refused() {
        // The literals here are deliberate. Comparing against `MAX_SKIP`
        // would make the test move whenever the constant moves, so raising
        // the bound would silently keep the test green — which is exactly
        // what a break-check probe caught it doing.
        assert_eq!(MAX_SKIP, 1_000, "the documented per-step bound");
        assert_eq!(MAX_SKIP_TOTAL, 2_000, "the documented total bound");

        for claim in [1_001u32, 100_000, u32::MAX / 2] {
            let (mut alice, mut bob, _ar, mut br) = pair();
            let (mut h, _) = alice.send_step().expect("chain");
            h.n = claim;
            assert!(
                matches!(
                    bob.recv_step(&h, &mut br).unwrap_err(),
                    RatchetError::TooManySkipped(_)
                ),
                "a claim of {claim} skips was accepted"
            );
        }

        // And the largest legal claim still works, so the bound is a bound and
        // not a blanket refusal.
        let (mut alice, mut bob, _ar, mut br) = pair();
        let (mut h, _) = alice.send_step().expect("chain");
        h.n = 1_000;
        assert!(bob.recv_step(&h, &mut br).is_ok());
    }

    #[test]
    fn the_skipped_cache_is_globally_bounded() {
        let (mut alice, mut bob, mut ar, mut br) = pair();
        let mut banked = 0usize;

        // Each round Alice sends MAX_SKIP messages of which Bob sees only the
        // last, banking MAX_SKIP - 1 — all WITHIN ONE EPOCH.
        //
        // The epoch used to turn between rounds, and that is no longer a route
        // to the bound: a step now drops keys older than the epoch it ends, so
        // cross-epoch accumulation plateaus at two epochs' worth by design.
        // Staying in one epoch tests the ceiling that ageing does not enforce,
        // which is the one this test is named for.
        let _ = &mut ar;
        for round in 0..4 {
            let mut last = None;
            for _ in 0..MAX_SKIP {
                last = Some(alice.send_step().expect("chain"));
            }
            let (h, _) = last.expect("at least one");
            match bob.recv_step(&h, &mut br) {
                Ok(_) => {
                    banked = bob.skipped_len();
                    assert!(
                        banked <= MAX_SKIP_TOTAL,
                        "round {round}: cache grew to {banked}"
                    );
                }
                Err(RatchetError::TooManySkipped(_)) => return, // refused, as designed
                Err(e) => panic!("round {round}: unexpected {e:?}"),
            }
        }
        panic!("the cache never hit its bound after 4 rounds (banked {banked})");
    }

    #[test]
    fn the_bank_forgets_epochs_it_has_ratcheted_past() {
        // A skipped key only ever left the bank when its message arrived, so
        // keys for messages that never came stayed for the life of the
        // conversation. Measured on a real profile: 324 banked keys across 42
        // epochs, none in the current one, in a 23 KB state the host rewrites
        // WHOLE on every advance into a container that cannot reuse the slots
        // it frees. Two epochs are kept; older ones are gone.
        let (mut alice, mut bob, mut ar, mut br) = pair();

        // Epoch 1: Alice sends two, Bob sees only the second — one key banked.
        let (_skipped_1, _) = alice.send_step().expect("chain");
        let (h1, _) = alice.send_step().expect("chain");
        bob.recv_step(&h1, &mut br).expect("a→b");
        assert_eq!(bob.skipped_len(), 1, "the unseen first message is banked");
        let (epochs, current) = bob.skipped_epochs();
        assert_eq!((epochs, current), (1, 1), "banked under the live epoch");

        // Turn the epoch once: the key is one epoch back, still reachable.
        let (hb, _) = bob.send_step().expect("chain");
        alice.recv_step(&hb, &mut ar).expect("b→a");
        let (_skipped_2, _) = alice.send_step().expect("chain");
        let (h2, _) = alice.send_step().expect("chain");
        bob.recv_step(&h2, &mut br).expect("a→b (epoch 2)");
        assert_eq!(
            bob.skipped_len(),
            2,
            "the ending epoch's key is kept — a straggler can still turn up",
        );

        // Turn it again: the first epoch is now two back and is dropped, while
        // the second one's key survives.
        let (hb2, _) = bob.send_step().expect("chain");
        alice.recv_step(&hb2, &mut ar).expect("b→a");
        let (_skipped_3, _) = alice.send_step().expect("chain");
        let (h3, _) = alice.send_step().expect("chain");
        bob.recv_step(&h3, &mut br).expect("a→b (epoch 3)");
        assert_eq!(
            bob.skipped_len(),
            2,
            "two epochs' worth, not three — the bank stopped growing",
        );
        let (epochs, _) = bob.skipped_epochs();
        assert_eq!(epochs, 2, "and it spans exactly the two kept epochs");
    }

    #[test]
    fn self_healing_a_leaked_state_loses_access_after_a_round_trip() {
        let (mut alice, mut bob, mut ar, mut br) = pair();
        let (h, _) = alice.send_step().expect("chain");
        bob.recv_step(&h, &mut br).expect("a→b");

        // Snapshot Bob's whole state — the compromise.
        let mut stolen = bob.clone();
        let mut stolen_rng = TestRng::new(0xC1);

        // One full round trip that the thief does not participate in.
        let (hb, _) = bob.send_step().expect("chain");
        alice.recv_step(&hb, &mut ar).expect("b→a");
        let (ha, _) = alice.send_step().expect("chain");
        bob.recv_step(&ha, &mut br).expect("a→b");
        let (hb2, _) = bob.send_step().expect("chain");
        alice.recv_step(&hb2, &mut ar).expect("b→a");

        // Now a fresh message. The thief's copy derives a different key,
        // because Bob re-keyed the root from ML-KEM and X25519 secrets the
        // thief never saw.
        let (ha2, mk_real) = alice.send_step().expect("chain");
        // Either the thief derives a different key, or they fall off the chain
        // outright. Both mean the same thing: the snapshot is stale.
        if let Ok(k) = stolen.recv_step(&ha2, &mut stolen_rng) {
            assert_ne!(
                *k, *mk_real,
                "a stolen snapshot must not track the live session"
            );
        }
        assert_eq!(
            *mk_real,
            *bob.recv_step(&ha2, &mut br)
                .expect("live session still works"),
        );
    }

    #[test]
    fn the_post_quantum_epoch_rotates_on_every_step() {
        // Self-healing on its own does not prove the ML-KEM leg contributes to
        // it: with the post-quantum epoch frozen, the X25519 rotation alone
        // still heals the session, and a break-check probe that froze it stayed
        // green. Post-compromise recovery has to survive an adversary who has
        // broken X25519 outright, so the ML-KEM half must rotate on its own
        // account — which is what this pins.
        let (mut alice, mut bob, mut ar, mut br) = pair();

        let mut seeds = vec![*bob.pq_seed()];
        let mut eks = vec![*bob.pq_ek()];

        for turn in 0..4 {
            let (h, _) = alice.send_step().expect("chain");
            bob.recv_step(&h, &mut br).expect("a→b");

            let seed = *bob.pq_seed();
            let ek = *bob.pq_ek();
            assert!(
                !seeds.contains(&seed),
                "turn {turn}: the ML-KEM seed was reused"
            );
            assert!(
                !eks.contains(&ek),
                "turn {turn}: the ML-KEM encapsulation key was reused"
            );
            seeds.push(seed);
            eks.push(ek);

            let (h, _) = bob.send_step().expect("chain");
            alice.recv_step(&h, &mut ar).expect("b→a");
        }

        // And the retired seed is genuinely retired: a ciphertext encapsulated
        // to the current key does not open under the previous one.
        let current = eks.last().expect("at least one");
        let (ss, ct) = crate::pq::encapsulate_to(current, &mut br).expect("valid key");
        let retired = crate::pq::PqEpoch::restore(&seeds[seeds.len() - 2], None);
        assert_ne!(
            retired.decapsulate(&ct),
            ss,
            "a retired ML-KEM seed must not open traffic from the current epoch"
        );
    }

    #[test]
    fn the_x25519_ratchet_key_rotates_on_every_step() {
        let (mut alice, mut bob, mut ar, mut br) = pair();
        let mut keys = vec![bob.dh_pk()];
        for turn in 0..4 {
            let (h, _) = alice.send_step().expect("chain");
            bob.recv_step(&h, &mut br).expect("a→b");
            let pk = bob.dh_pk();
            assert!(!keys.contains(&pk), "turn {turn}: ratchet key was reused");
            keys.push(pk);
            let (h, _) = bob.send_step().expect("chain");
            alice.recv_step(&h, &mut ar).expect("b→a");
        }
    }

    #[test]
    fn a_low_order_peer_key_is_refused() {
        let root = [1u8; KEY_LEN];
        let mut rng = TestRng::new(0xD1);
        assert_eq!(
            RatchetCore::initiator(&root, &[0u8; 32], &mut rng).unwrap_err(),
            RatchetError::NonContributory
        );

        let (mut alice, mut bob, _ar, mut br) = pair();
        let (mut h, _) = alice.send_step().expect("chain");
        h.dh_pk = [0u8; 32];
        assert_eq!(
            bob.recv_step(&h, &mut br).unwrap_err(),
            RatchetError::NonContributory
        );
    }

    #[test]
    fn debug_does_not_leak_key_material() {
        let (alice, _bob, _ar, _br) = pair();
        let rendered = format!("{alice:?}");
        assert!(rendered.contains("skipped"));
        for byte_pair in ["42424242", "0000000000000000"] {
            assert!(
                !rendered.contains(byte_pair) || rendered.len() < 200,
                "debug output looks like it contains raw key bytes: {rendered}"
            );
        }
    }
}
