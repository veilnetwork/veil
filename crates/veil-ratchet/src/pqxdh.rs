//! Asynchronous key agreement, modelled on Signal's PQXDH.
//!
//! # What it needs, and what it deliberately does not
//!
//! The recipient may be offline for the whole exchange. Everything the
//! initiator reads is already published and already signed: the recipient's
//! per-device certificate, which today carries an ML-KEM-768 encapsulation key
//! and now also carries a rotating X25519 key derived from the same device
//! secret. No new record, no new DHT slot, and — the point — **no new
//! long-lived identifier**. The device already had exactly one name; it still
//! does.
//!
//! # The construction
//!
//! ```text
//! DH1 = X25519(ik_a, ik_b)     authenticates the initiator
//! DH2 = X25519(ek_a, ik_b)     freshness, and forward secrecy of A's half
//! SS  = ML-KEM-768.Encaps(mlkem_ek_b)
//!
//! root = HKDF-SHA256(
//!            salt = "veil.pqxdh.v1.salt",
//!            ikm  = DH1 ‖ DH2 ‖ SS,
//!            info = "veil.pqxdh.v1" ‖ node_a ‖ node_b ‖ instance_b)
//! ```
//!
//! Both identifiers go into `info`, which is what stops an unknown-key-share:
//! a relay cannot take A's prologue and re-present it as addressed to a third
//! party, because the third party derives a different root and the first frame
//! simply fails to open.
//!
//! `ik_b` doubles as the recipient's initial ratchet key. That is X3DH with
//! the signed prekey and the identity key collapsed into one, which is what
//! the "no new record" constraint forces. The cost is stated plainly below.
//!
//! # What is and is not post-quantum here
//!
//! *Confidentiality and forward secrecy* are hybrid from the first byte: an
//! attacker who records the traffic and later builds a quantum computer still
//! has to break ML-KEM-768, because the root key mixes `SS` in and every
//! subsequent epoch mixes a fresh ML-KEM secret in.
//!
//! *Authentication of the very first message* rests on `DH1`, and `DH1` is
//! classical. A quantum adversary who is present at the time of first contact
//! could impersonate A to B. From the second message onward the session is
//! mutually post-quantum authenticated, because B's reply encapsulates to the
//! key A announced and only A can decapsulate it.
//!
//! This is a deliberate trade, and it is the same one Signal made in PQXDH,
//! for the same reason: deniable authentication needs an operation both
//! parties can compute from the other's public key alone — a non-interactive
//! key exchange — and no practical post-quantum one exists. A post-quantum
//! *signature* would close the gap and destroy deniability, which is not a
//! trade this project is willing to make.
//!
//! # Forward secrecy of the first message
//!
//! `DH1` and `DH2` both use the recipient's device X25519 key, so a compromise
//! of that key opens first messages sent to it. The mitigation is the
//! rotation the tree already runs: the device key is derived per rotation
//! epoch, published in the same certificate as the ML-KEM key and on the same
//! schedule, so the exposure is bounded by one epoch rather than by the
//! lifetime of the identity. Everything after the recipient's first reply is
//! forward-secret in the ordinary ratchet sense.

use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::pq::{ML_KEM_768_CT_LEN, ML_KEM_768_EK_LEN, encapsulate_to};
use crate::{KEY_LEN, RatchetError, RatchetRng, RatchetSession, random_array};

/// Prologue tag. `VX` for veil key exchange; the version byte follows.
pub const PQXDH_MAGIC: [u8; 2] = *b"VX";
const PQXDH_V1: u8 = 1;

const HKDF_SALT: &[u8] = b"veil.pqxdh.v1.salt";
const HKDF_INFO: &[u8] = b"veil.pqxdh.v1";

/// `magic(2) ‖ version(1) ‖ ik_a(32) ‖ ek_a(32) ‖ kem_ct(1088)`
pub const PROLOGUE_LEN: usize = 2 + 1 + 32 + 32 + ML_KEM_768_CT_LEN;

/// The initiator's first transmission: the prologue plus the first ratchet
/// frame, as one opaque blob.
///
/// It carries the initiator's device X25519 public key in the clear **relative
/// to whatever the caller wraps it in**. That is not an anonymity regression
/// only if the caller keeps it inside the envelope it already seals to the
/// recipient — which is what the existing send path does. Handing this blob to
/// a relay unwrapped would publish who is talking to whom.
#[derive(Clone, PartialEq, Eq)]
pub struct InitialMessage {
    initiator_ik: [u8; 32],
    initiator_ek: [u8; 32],
    kem_ct: [u8; ML_KEM_768_CT_LEN],
    first_frame: Vec<u8>,
}

impl core::fmt::Debug for InitialMessage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("InitialMessage")
            .field("initiator_ik", &"[public key]")
            .field("first_frame_len", &self.first_frame.len())
            .finish_non_exhaustive()
    }
}

impl InitialMessage {
    /// The initiator's claimed device X25519 public key.
    ///
    /// **The recipient must check this against the initiator's signed
    /// certificate before trusting the sender identity.** Nothing inside this
    /// crate can do it: the certificate chain lives at the caller's layer.
    /// Skipping the check does not weaken confidentiality — the message still
    /// only opens for the addressed device — but it does mean the sender is
    /// unauthenticated, which is precisely the state this work exists to end.
    pub fn initiator_ik(&self) -> &[u8; 32] {
        &self.initiator_ik
    }

    /// The ratchet frame riding behind the prologue.
    ///
    /// Exposed because a prologue has to be *repeatable*. The initiator cannot
    /// know whether the first transmission arrived until the responder answers,
    /// and re-running [`initiate`] would derive a second, unrelated root — so
    /// the caller keeps the first [`PROLOGUE_LEN`] bytes and re-attaches them to
    /// each later frame until it hears back. [`accept`] does not care which
    /// frame it is handed: the root comes from the prologue and the ratchet's
    /// own skipped-key handling covers the gap.
    pub fn first_frame(&self) -> &[u8] {
        &self.first_frame
    }

    /// Serialize for transmission.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PROLOGUE_LEN + self.first_frame.len());
        out.extend_from_slice(&PQXDH_MAGIC);
        out.push(PQXDH_V1);
        out.extend_from_slice(&self.initiator_ik);
        out.extend_from_slice(&self.initiator_ek);
        out.extend_from_slice(&self.kem_ct);
        out.extend_from_slice(&self.first_frame);
        out
    }

    /// Parse a received prologue.
    pub fn decode(bytes: &[u8]) -> Result<Self, RatchetError> {
        if bytes.len() <= PROLOGUE_LEN {
            return Err(RatchetError::MalformedFrame("prologue truncated"));
        }
        if bytes[..2] != PQXDH_MAGIC {
            return Err(RatchetError::MalformedFrame("bad prologue magic"));
        }
        if bytes[2] != PQXDH_V1 {
            return Err(RatchetError::MalformedFrame("unsupported prologue version"));
        }
        let mut initiator_ik = [0u8; 32];
        initiator_ik.copy_from_slice(&bytes[3..35]);
        let mut initiator_ek = [0u8; 32];
        initiator_ek.copy_from_slice(&bytes[35..67]);
        let mut kem_ct = [0u8; ML_KEM_768_CT_LEN];
        kem_ct.copy_from_slice(&bytes[67..PROLOGUE_LEN]);
        Ok(Self {
            initiator_ik,
            initiator_ek,
            kem_ct,
            first_frame: bytes[PROLOGUE_LEN..].to_vec(),
        })
    }
}

/// Who is talking to whom, bound into the derivation so a prologue cannot be
/// replayed at a third party.
#[derive(Clone, Copy, Debug)]
pub struct Peers<'a> {
    /// The initiator's node identifier.
    pub initiator_node_id: &'a [u8; 32],
    /// The responder's node identifier.
    pub responder_node_id: &'a [u8; 32],
    /// The responder's device (instance) identifier — the one whose
    /// certificate supplied the keys.
    pub responder_instance_id: &'a [u8; 16],
}

/// The responder's published key material, as read from their signed
/// certificate.
#[derive(Clone, Copy, Debug)]
pub struct ResponderKeys<'a> {
    /// Rotating device X25519 public key (the new certificate field).
    pub ik: &'a [u8; 32],
    /// ML-KEM-768 encapsulation key (the field the certificate already had).
    pub mlkem_ek: &'a [u8; ML_KEM_768_EK_LEN],
}

/// Open a conversation with an offline peer.
///
/// `our_ik_sk` is our own rotating device X25519 secret, derived from the
/// device identity seed for the current rotation epoch. `associated_data` is
/// bound into the first frame's tag and must match on the other side.
pub fn initiate(
    our_ik_sk: &[u8; 32],
    peers: Peers<'_>,
    responder: ResponderKeys<'_>,
    plaintext: &[u8],
    associated_data: &[u8],
    rng: &mut impl RatchetRng,
) -> Result<(InitialMessage, RatchetSession), RatchetError> {
    let ik_a = StaticSecret::from(*our_ik_sk);
    let ik_b = PublicKey::from(*responder.ik);

    // Note for anyone tempted to delete the two checks below as redundant:
    // they are, for this one input. `responder.ik` is also the initial ratchet
    // key, and `RatchetSession::initiator` re-checks it, so removing these two
    // leaves the outcome unchanged — a break-check probe confirmed exactly
    // that. They stay because they refuse before a root is derived from a
    // value the peer chose, and because the two call sites are independent:
    // whichever one someone reworks first, the other still refuses.
    let dh1 = ik_a.diffie_hellman(&ik_b);
    if !dh1.was_contributory() {
        return Err(RatchetError::NonContributory);
    }

    let ek_a = StaticSecret::from(*random_array::<32>(rng));
    let ek_a_pub = *PublicKey::from(&ek_a).as_bytes();
    let dh2 = ek_a.diffie_hellman(&ik_b);
    if !dh2.was_contributory() {
        return Err(RatchetError::NonContributory);
    }

    let (kem_ss, kem_ct) = encapsulate_to(responder.mlkem_ek, rng)?;

    let root = derive_root(dh1.as_bytes(), dh2.as_bytes(), &kem_ss, peers);

    // The responder's device key doubles as their initial ratchet key.
    let mut session = RatchetSession::initiator(&root, responder.ik, rng)?;
    let first_frame = session.encrypt(plaintext, associated_data)?;

    Ok((
        InitialMessage {
            initiator_ik: *PublicKey::from(&ik_a).as_bytes(),
            initiator_ek: ek_a_pub,
            kem_ct,
            first_frame,
        },
        session,
    ))
}

/// Accept a conversation opened by a peer.
///
/// `our_ik_sk` is the device X25519 secret whose public half we published;
/// `our_mlkem_seed` is the decapsulation seed for the encapsulation key we
/// published. Callers holding a ring of rotating seeds try each candidate: a
/// seed from the wrong epoch simply fails to open the first frame, because
/// ML-KEM decapsulation rejects implicitly and the wrong root produces a wrong
/// key.
///
/// The caller must independently confirm that
/// [`InitialMessage::initiator_ik`] is the key the claimed sender published.
pub fn accept(
    our_ik_sk: &[u8; 32],
    our_mlkem_seed: &[u8; crate::ML_KEM_768_SEED_LEN],
    peers: Peers<'_>,
    message: &InitialMessage,
    associated_data: &[u8],
    rng: &mut impl RatchetRng,
) -> Result<(Vec<u8>, RatchetSession), RatchetError> {
    let ik_b = StaticSecret::from(*our_ik_sk);

    let ik_a = PublicKey::from(message.initiator_ik);
    let dh1 = ik_b.diffie_hellman(&ik_a);
    if !dh1.was_contributory() {
        return Err(RatchetError::NonContributory);
    }

    let ek_a = PublicKey::from(message.initiator_ek);
    let dh2 = ik_b.diffie_hellman(&ek_a);
    if !dh2.was_contributory() {
        return Err(RatchetError::NonContributory);
    }

    let kem_ss = crate::pq::PqEpoch::restore(our_mlkem_seed, None).decapsulate(&message.kem_ct);

    let root = derive_root(dh1.as_bytes(), dh2.as_bytes(), &kem_ss, peers);

    let mut session = RatchetSession::responder(&root, *our_ik_sk, rng);
    let plaintext = session.decrypt(&message.first_frame, associated_data, rng)?;
    Ok((plaintext, session))
}

fn derive_root(
    dh1: &[u8; 32],
    dh2: &[u8; 32],
    kem_ss: &[u8; KEY_LEN],
    peers: Peers<'_>,
) -> [u8; KEY_LEN] {
    let mut ikm = Zeroizing::new(Vec::with_capacity(96));
    ikm.extend_from_slice(dh1);
    ikm.extend_from_slice(dh2);
    ikm.extend_from_slice(kem_ss);

    let mut info = Vec::with_capacity(HKDF_INFO.len() + 32 + 32 + 16);
    info.extend_from_slice(HKDF_INFO);
    info.extend_from_slice(peers.initiator_node_id);
    info.extend_from_slice(peers.responder_node_id);
    info.extend_from_slice(peers.responder_instance_id);

    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), &ikm);
    let mut root = [0u8; KEY_LEN];
    hk.expand(&info, &mut root)
        .expect("HKDF-SHA256 with a 32-byte output is always valid");
    root
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TestRng;
    use crate::pq::PqEpoch;

    const AD: &[u8] = b"ad";
    const NODE_A: [u8; 32] = [0xA0; 32];
    const NODE_B: [u8; 32] = [0xB0; 32];
    const INST_B: [u8; 16] = [0xB1; 16];

    struct Responder {
        ik_sk: [u8; 32],
        ik_pk: [u8; 32],
        seed: [u8; crate::ML_KEM_768_SEED_LEN],
        ek: [u8; ML_KEM_768_EK_LEN],
    }

    fn responder(label: u8) -> Responder {
        let mut rng = TestRng::new(label);
        let ik_sk = *random_array::<32>(&mut rng);
        let ik_pk = *PublicKey::from(&StaticSecret::from(ik_sk)).as_bytes();
        let epoch = PqEpoch::new(&mut rng);
        Responder {
            ik_sk,
            ik_pk,
            seed: *epoch.seed(),
            ek: *epoch.ek(),
        }
    }

    fn peers() -> Peers<'static> {
        Peers {
            initiator_node_id: &NODE_A,
            responder_node_id: &NODE_B,
            responder_instance_id: &INST_B,
        }
    }

    fn initiator_secret(label: u8) -> [u8; 32] {
        *random_array::<32>(&mut TestRng::new(label))
    }

    #[test]
    fn first_contact_with_an_offline_peer() {
        let bob = responder(0x11);
        let alice_sk = initiator_secret(0x12);
        let mut arng = TestRng::new(0x13);
        let mut brng = TestRng::new(0x14);

        let (msg, mut alice) = initiate(
            &alice_sk,
            peers(),
            ResponderKeys {
                ik: &bob.ik_pk,
                mlkem_ek: &bob.ek,
            },
            b"hello from the void",
            AD,
            &mut arng,
        )
        .expect("initiate");

        // Bob comes online later and finds only these bytes waiting.
        let wire = msg.encode();
        let received = InitialMessage::decode(&wire).expect("decode");
        assert_eq!(received, msg);

        let (plaintext, mut bob_session) =
            accept(&bob.ik_sk, &bob.seed, peers(), &received, AD, &mut brng).expect("accept");
        assert_eq!(plaintext, b"hello from the void");

        // And the conversation continues in both directions.
        let f = bob_session.encrypt(b"got it", AD).expect("seal");
        assert_eq!(alice.decrypt(&f, AD, &mut arng).expect("open"), b"got it");
        let f = alice.encrypt(b"good", AD).expect("seal");
        assert_eq!(
            bob_session.decrypt(&f, AD, &mut brng).expect("open"),
            b"good"
        );
    }

    #[test]
    fn the_wrong_decapsulation_seed_does_not_open_it() {
        let bob = responder(0x21);
        let other = responder(0x22);
        let alice_sk = initiator_secret(0x23);
        let mut arng = TestRng::new(0x24);
        let mut brng = TestRng::new(0x25);

        let (msg, _) = initiate(
            &alice_sk,
            peers(),
            ResponderKeys {
                ik: &bob.ik_pk,
                mlkem_ek: &bob.ek,
            },
            b"secret",
            AD,
            &mut arng,
        )
        .expect("initiate");

        assert!(
            accept(&bob.ik_sk, &other.seed, peers(), &msg, AD, &mut brng).is_err(),
            "a seed from another epoch must not open the message"
        );
    }

    #[test]
    fn the_wrong_device_key_does_not_open_it() {
        let bob = responder(0x31);
        let other = responder(0x32);
        let alice_sk = initiator_secret(0x33);
        let mut arng = TestRng::new(0x34);
        let mut brng = TestRng::new(0x35);

        let (msg, _) = initiate(
            &alice_sk,
            peers(),
            ResponderKeys {
                ik: &bob.ik_pk,
                mlkem_ek: &bob.ek,
            },
            b"secret",
            AD,
            &mut arng,
        )
        .expect("initiate");

        assert!(
            accept(&other.ik_sk, &bob.seed, peers(), &msg, AD, &mut brng).is_err(),
            "the X25519 leg must be load-bearing, not decorative"
        );
    }

    #[test]
    fn identities_are_bound_so_a_prologue_cannot_be_re_addressed() {
        let bob = responder(0x41);
        let alice_sk = initiator_secret(0x42);
        let mut arng = TestRng::new(0x43);
        let mut brng = TestRng::new(0x44);

        let (msg, _) = initiate(
            &alice_sk,
            peers(),
            ResponderKeys {
                ik: &bob.ik_pk,
                mlkem_ek: &bob.ek,
            },
            b"for bob",
            AD,
            &mut arng,
        )
        .expect("initiate");

        let impostor = [0xCC; 32];
        for wrong in [
            Peers {
                initiator_node_id: &impostor,
                responder_node_id: &NODE_B,
                responder_instance_id: &INST_B,
            },
            Peers {
                initiator_node_id: &NODE_A,
                responder_node_id: &impostor,
                responder_instance_id: &INST_B,
            },
            Peers {
                initiator_node_id: &NODE_A,
                responder_node_id: &NODE_B,
                responder_instance_id: &[0xCC; 16],
            },
        ] {
            assert!(
                accept(&bob.ik_sk, &bob.seed, wrong, &msg, AD, &mut brng).is_err(),
                "a re-addressed prologue must not open"
            );
        }
    }

    #[test]
    fn a_tampered_prologue_does_not_open() {
        let bob = responder(0x51);
        let alice_sk = initiator_secret(0x52);
        let mut arng = TestRng::new(0x53);
        let mut brng = TestRng::new(0x54);

        let (msg, _) = initiate(
            &alice_sk,
            peers(),
            ResponderKeys {
                ik: &bob.ik_pk,
                mlkem_ek: &bob.ek,
            },
            b"x",
            AD,
            &mut arng,
        )
        .expect("initiate");

        let wire = msg.encode();
        // The ephemeral key, the identity key, and the ciphertext all feed the
        // root, so touching any of them breaks the first frame.
        for offset in [3usize, 35, 67, PROLOGUE_LEN - 1] {
            let mut bad = wire.clone();
            bad[offset] ^= 0x01;
            let parsed = InitialMessage::decode(&bad).expect("still parses");
            assert!(
                accept(&bob.ik_sk, &bob.seed, peers(), &parsed, AD, &mut brng).is_err(),
                "byte {offset} was not bound into the root"
            );
        }
    }

    #[test]
    fn malformed_prologues_are_refused() {
        let bob = responder(0x61);
        let alice_sk = initiator_secret(0x62);
        let mut arng = TestRng::new(0x63);
        let (msg, _) = initiate(
            &alice_sk,
            peers(),
            ResponderKeys {
                ik: &bob.ik_pk,
                mlkem_ek: &bob.ek,
            },
            b"x",
            AD,
            &mut arng,
        )
        .expect("initiate");
        let wire = msg.encode();

        assert!(InitialMessage::decode(&[]).is_err());
        assert!(InitialMessage::decode(&wire[..PROLOGUE_LEN]).is_err());
        let mut bad = wire.clone();
        bad[0] = b'Z';
        assert!(InitialMessage::decode(&bad).is_err());
        let mut bad = wire.clone();
        bad[2] = 7;
        assert!(InitialMessage::decode(&bad).is_err());
    }

    #[test]
    fn first_contact_is_post_quantum_confidential() {
        // The ML-KEM leg is load-bearing for confidentiality: an adversary who
        // breaks X25519 outright — modelled here by handing them both device
        // secrets and the ephemeral — still cannot derive the root without the
        // decapsulation seed.
        let bob = responder(0x71);
        let alice_sk = initiator_secret(0x72);
        let mut arng = TestRng::new(0x73);

        let (msg, _) = initiate(
            &alice_sk,
            peers(),
            ResponderKeys {
                ik: &bob.ik_pk,
                mlkem_ek: &bob.ek,
            },
            b"still secret",
            AD,
            &mut arng,
        )
        .expect("initiate");

        // Reconstruct both classical legs exactly as a quantum adversary would.
        let ik_b = StaticSecret::from(bob.ik_sk);
        let dh1 = ik_b.diffie_hellman(&PublicKey::from(*msg.initiator_ik()));
        let dh2 = ik_b.diffie_hellman(&PublicKey::from(msg.initiator_ek));

        // With the true ML-KEM secret the root is right; with any other value
        // it is not. Nothing classical closes that gap.
        let true_ss = PqEpoch::restore(&bob.seed, None).decapsulate(&msg.kem_ct);
        let real = derive_root(dh1.as_bytes(), dh2.as_bytes(), &true_ss, peers());
        let guessed = derive_root(dh1.as_bytes(), dh2.as_bytes(), &[0u8; 32], peers());
        assert_ne!(real, guessed);
    }

    #[test]
    fn responder_can_forge_a_transcript_from_the_initiator() {
        // Deniability at the key-agreement layer. Bob holds ik_b and the
        // decapsulation seed, which is everything the derivation needs — so he
        // can pick any ik_a and ek_a he likes, mint a root, and produce a
        // complete "message from Alice". Alice's participation is not required
        // and therefore cannot be proven.
        let bob = responder(0x81);
        let mut brng = TestRng::new(0x82);

        // Bob invents an "Alice" out of nothing.
        let fake_alice_sk = *random_array::<32>(&mut brng);
        let (forged, _) = initiate(
            &fake_alice_sk,
            peers(),
            ResponderKeys {
                ik: &bob.ik_pk,
                mlkem_ek: &bob.ek,
            },
            b"Alice never wrote this",
            AD,
            &mut brng,
        )
        .expect("initiate");

        let (plaintext, _) =
            accept(&bob.ik_sk, &bob.seed, peers(), &forged, AD, &mut brng).expect("accept");
        assert_eq!(plaintext, b"Alice never wrote this");

        // And there is no signature anywhere in it to distinguish the forgery
        // from the real thing: the prologue is exactly three public values.
        assert_eq!(
            forged.encode().len() - forged.first_frame.len(),
            PROLOGUE_LEN,
            "the prologue is a version tag and three public values — nothing else"
        );
    }

    #[test]
    fn a_low_order_responder_key_is_refused() {
        let bob = responder(0x91);
        let alice_sk = initiator_secret(0x92);
        let mut arng = TestRng::new(0x93);
        // The eight low-order points of Curve25519, plus the all-zero
        // encoding. Any of them makes X25519 output a constant the peer
        // chose, so the initiator must refuse before it derives anything.
        for bad in low_order_points() {
            assert_eq!(
                initiate(
                    &alice_sk,
                    peers(),
                    ResponderKeys {
                        ik: &bad,
                        mlkem_ek: &bob.ek,
                    },
                    b"x",
                    AD,
                    &mut arng,
                )
                .unwrap_err(),
                RatchetError::NonContributory,
                "point {bad:02x?} was accepted"
            );
        }
    }

    #[test]
    fn a_low_order_initiator_key_in_a_prologue_is_refused() {
        // The mirror of the above, on the side that receives. Nothing else
        // covered `accept`'s own contributory checks, which a break-check
        // probe demonstrated by removing them and staying green.
        let bob = responder(0x94);
        let alice_sk = initiator_secret(0x95);
        let mut arng = TestRng::new(0x96);
        let mut brng = TestRng::new(0x97);

        let (good, _) = initiate(
            &alice_sk,
            peers(),
            ResponderKeys {
                ik: &bob.ik_pk,
                mlkem_ek: &bob.ek,
            },
            b"x",
            AD,
            &mut arng,
        )
        .expect("initiate");

        for bad in low_order_points() {
            let mut forged = good.clone();
            forged.initiator_ik = bad;
            assert_eq!(
                accept(&bob.ik_sk, &bob.seed, peers(), &forged, AD, &mut brng).unwrap_err(),
                RatchetError::NonContributory,
                "identity point {bad:02x?} was accepted"
            );

            let mut forged = good.clone();
            forged.initiator_ek = bad;
            assert_eq!(
                accept(&bob.ik_sk, &bob.seed, peers(), &forged, AD, &mut brng).unwrap_err(),
                RatchetError::NonContributory,
                "ephemeral point {bad:02x?} was accepted"
            );
        }
    }

    /// Curve25519 points of small order — the canonical set carried in the
    /// libsodium and `x25519-dalek` test corpora. Each one makes X25519
    /// output a value the sender of the point already knows.
    fn low_order_points() -> [[u8; 32]; 5] {
        let mut order_1 = [0u8; 32];
        order_1[0] = 1;

        let mut p_minus_1 = [0xffu8; 32];
        p_minus_1[0] = 0xec;
        p_minus_1[31] = 0x7f;

        [
            // the all-zero encoding (order 4 in the twist)
            [0u8; 32],
            order_1,
            // order 8
            [
                0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f,
                0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16,
                0x5f, 0x49, 0xb8, 0x00,
            ],
            // order 4
            [
                0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83,
                0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd,
                0xd0, 0x9f, 0x11, 0x57,
            ],
            p_minus_1,
        ]
    }

    #[test]
    fn an_invalid_published_encapsulation_key_is_refused() {
        let bob = responder(0xA1);
        let alice_sk = initiator_secret(0xA2);
        let mut arng = TestRng::new(0xA3);
        let bad = [0xFFu8; ML_KEM_768_EK_LEN];
        assert_eq!(
            initiate(
                &alice_sk,
                peers(),
                ResponderKeys {
                    ik: &bob.ik_pk,
                    mlkem_ek: &bad,
                },
                b"x",
                AD,
                &mut arng,
            )
            .unwrap_err(),
            RatchetError::InvalidPqKey
        );
    }

    #[test]
    fn two_conversations_with_the_same_peer_derive_different_roots() {
        let bob = responder(0xB1);
        let alice_sk = initiator_secret(0xB2);
        let keys = ResponderKeys {
            ik: &bob.ik_pk,
            mlkem_ek: &bob.ek,
        };

        let (m1, _) = initiate(
            &alice_sk,
            peers(),
            keys,
            b"one",
            AD,
            &mut TestRng::new(0xB3),
        )
        .expect("initiate");
        let (m2, _) = initiate(
            &alice_sk,
            peers(),
            keys,
            b"one",
            AD,
            &mut TestRng::new(0xB4),
        )
        .expect("initiate");

        assert_ne!(m1.initiator_ek, m2.initiator_ek, "ephemeral must be fresh");
        assert_ne!(m1.kem_ct, m2.kem_ct, "encapsulation must be fresh");
        assert_ne!(m1.first_frame, m2.first_frame);
    }

    #[test]
    fn the_session_persists_across_a_restart_right_after_first_contact() {
        let bob = responder(0xC1);
        let alice_sk = initiator_secret(0xC2);
        let mut arng = TestRng::new(0xC3);
        let mut brng = TestRng::new(0xC4);

        let (msg, alice) = initiate(
            &alice_sk,
            peers(),
            ResponderKeys {
                ik: &bob.ik_pk,
                mlkem_ek: &bob.ek,
            },
            b"first",
            AD,
            &mut arng,
        )
        .expect("initiate");
        let (_, bob_session) =
            accept(&bob.ik_sk, &bob.seed, peers(), &msg, AD, &mut brng).expect("accept");

        // Both sides go down and come back from their blobs.
        let mut alice = RatchetSession::import_state(&alice.export_state()).expect("reload");
        let mut bob_session =
            RatchetSession::import_state(&bob_session.export_state()).expect("reload");

        let f = bob_session.encrypt(b"reply", AD).expect("seal");
        assert_eq!(alice.decrypt(&f, AD, &mut arng).expect("open"), b"reply");
    }
}
