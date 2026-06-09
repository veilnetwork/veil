//! Multi-hop circuit envelope.
//!
//! Composes [`super::onion`] (single-hop AEAD) with a thin
//! next-hop-id encoding so each relay knows where to forward the
//! remaining ciphertext. No new crypto here — pure encoding on top
//! of the cryptographic floor laid in `onion.rs`.
//!
//! # The next-hop-id convention
//!
//! Each onion-layer plaintext is structured as:
//!
//! ```text
//! [0..32] next_hop_id (32 bytes — BLAKE3 of next hop's pubkey, or
//! all-zeros sentinel meaning "I am the final
//! hop, what follows is the actual payload")
//! [32..] inner — the next layer's onion envelope, OR the
//! actual payload if next_hop_id is the
//! sentinel
//! ```
//!
//! A relay calls [`peel_circuit`] which:
//! 1. Calls `onion::unwrap_at_hop` to decrypt one layer.
//! 2. Reads the first 32 bytes of plaintext as `next_hop_id`.
//! 3. If the sentinel: returns [`PeelResult::Final`] with the
//!    remaining bytes as the payload — this hop is the destination.
//! 4. Otherwise: returns [`PeelResult::Forward`] with `next_hop_id`
//!    and the remaining bytes — forward to that hop.
//!
//! The all-zeros sentinel was chosen because:
//! * It's trivially testable — no magic-byte invariants to remember.
//! * Real `node_id`s are BLAKE3 hashes; the all-zeros pre-image is
//!   vanishingly unlikely (probability < 2⁻²⁵⁶), so collision with
//!   a legitimate node is impossible in practice.
//! * A buggy sender that forgets to terminate the chain produces a
//!   payload starting with arbitrary bytes that will look like a
//!   "forward to that node" instruction — which the relay tries to
//!   forward and the bogus next hop discards because it can't decrypt.
//!   Loud failure mode; matches the rest of the codebase's "fail loud
//!   not silent".
//!
//! # Multi-hop builder
//!
//! [`build_circuit`] takes a payload and a list of `(node_id, pubkey)`
//! hop tuples and produces the outermost envelope. Wraps the payload
//! through hops in REVERSE order (last hop's plaintext is built first
//! with the sentinel; each preceding wrap layers the next-hop-id on
//! top).
//!
//! # Composes with cell
//!
//! The output of `build_circuit` is variable-size. Callers pack it
//! into a [`super::cell`] for fixed-size on-the-wire framing. For an
//! N-hop circuit + final payload P bytes, the envelope size is
//! `P + 32 + 60*N` (P + sentinel-prefix + N onion overheads).
//!
//! # What this module does NOT do (still scoped for follow-ups)
//!
//! * **No `CircuitId` for stateful circuits.** This module ships
//!   stateless single-message circuits (one onion = one message).
//!   Persistent circuits (build once, send N messages over) need
//!   a separate session-keyed encryption mode and belong in the
//!   full main piece.
//! * **No return-path / reply-path encoding.** This module is
//!   send-only; replies need a rendezvous-style return-onion
//!   or a one-shot `replyable: true` flag.
//! * **No padding to fixed size at the circuit layer.** Each layer
//!   is `len(inner) + 60` bytes — variable. Cell layer provides
//!   the fixed-size envelope.
//! * **No relay-directory lookup.** Caller supplies the hop
//!   tuples; discovering relays via DHT is.

use crate::onion::{self, OnionError};

/// Length of `next_hop_id` prefix in each layer's plaintext. Equal
/// to `NodeId` byte length — this module deals in raw `[u8; 32]` to
/// avoid pulling `cfg::NodeId` into the anonymity crate boundary
/// (the caller can convert at the API edge).
pub const NEXT_HOP_ID_LEN: usize = 32;

/// Sentinel `next_hop_id` indicating "this hop is the final destination
/// what follows is the actual payload". All-zeros is safe: real
/// node_ids are BLAKE3(pubkey) and the all-zeros pre-image is
/// cryptographically unreachable.
pub const FINAL_HOP_SENTINEL: [u8; NEXT_HOP_ID_LEN] = [0u8; NEXT_HOP_ID_LEN];

/// anti-loop TTL: hard cap on the per-layer
/// TTL field encoded in circuit envelopes. Honest senders set TTL =
/// `hops.len + 1` (small headroom). Receiver-side cap prevents an
/// adversarial sender from encoding a huge TTL and chaining self-loops
/// indefinitely — independent of the natural payload-shrinkage
/// limit that today caps loops at ~5-6 (cell-size budget). Sets the
/// maximum-amplification factor a single circuit can produce.
pub const MAX_CIRCUIT_TTL: u8 = 16;

/// Wire-layer overhead per layer for the TTL byte. : each
/// layer's plaintext now is `[ttl(1)][next_hop_id(32)][inner]`. Existing
/// `PER_HOP_OVERHEAD` constant is updated below to reflect the +1 byte.
pub const TTL_PREFIX_LEN: usize = 1;

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum CircuitError {
    #[error("onion: {0}")]
    Onion(OnionError),
    #[error("plaintext too short for next-hop-id prefix ({got} B < {min} B)")]
    PlaintextTooShort { got: usize, min: usize },
    #[error("circuit must have at least one hop")]
    NoHops,
    /// anti-loop TTL: incoming circuit envelope's TTL field is 0
    /// (would have been forwarded by-prevous-hop and decremented to 0; OR
    /// adversarial sender encoded TTL=0 directly). Drop the frame.
    #[error("circuit ttl exhausted")]
    TtlExhausted,
    /// anti-loop TTL: incoming TTL exceeds [`MAX_CIRCUIT_TTL`].
    /// Honest senders cap at `hops.len + 1`; values > 16 indicate
    /// malicious sender attempting to inflate amplification budget.
    #[error("circuit ttl {got} exceeds max {max}")]
    TtlExceedsCap { got: u8, max: u8 },
    /// anti-loop TTL: caller asked for a circuit longer than
    /// the TTL cap allows (`hops.len + 1 > MAX_CIRCUIT_TTL`). Reject
    /// at build time rather than letting the receiver silently drop.
    #[error("circuit too long for ttl cap ({hops} hops requires ttl {required} > max {max})")]
    CircuitTooLongForTtl { hops: usize, required: u8, max: u8 },
}

impl From<OnionError> for CircuitError {
    fn from(e: OnionError) -> Self {
        Self::Onion(e)
    }
}

/// Result of peeling one circuit layer.
///
/// `inner` (forward) and
/// `payload` (final) buffers hold post-AEAD-decrypt plaintext, which
/// is sensitive at the final hop. Both fields are `Zeroizing<Vec<u8>>`
/// so the bytes are wiped from memory on drop — important when the
/// consumer holds the value for any non-trivial time (e.g. in a
/// dispatcher mailbox queue) before forwarding or delivering.
/// `Zeroizing<Vec<u8>>` derefs transparently to `&[u8]` / `Vec<u8>`
/// in most read paths so consumers don't need invasive changes.
#[derive(Debug, PartialEq)]
pub enum PeelResult {
    /// This hop is an intermediate relay — forward `inner` to `next_hop`.
    Forward {
        next_hop: [u8; NEXT_HOP_ID_LEN],
        inner: zeroize::Zeroizing<Vec<u8>>,
    },
    /// This hop is the final destination — `payload` is the actual
    /// caller-supplied message.
    Final {
        payload: zeroize::Zeroizing<Vec<u8>>,
    },
}

/// One hop in the circuit: who they are (`node_id`) and how to encrypt
/// for them (`pubkey` — X25519 public key bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hop {
    pub node_id: [u8; NEXT_HOP_ID_LEN],
    pub pubkey: [u8; 32],
}

/// Build the outermost circuit envelope. `hops[0]` is the FIRST hop
/// (the one the sender's first transmission goes); `hops[N-1]` is
/// the FINAL hop that recovers the payload.
///
/// Returns the bytes the sender hands to `hops[0]`.
///
/// **anti-loop TTL:** each layer's plaintext leads with a 1-byte TTL set to a
/// CONSTANT [`MAX_CIRCUIT_TTL`] on every layer (audit cycle-4 M1 — a per-layer
/// value that varied with position previously leaked each hop's distance from
/// the destination and gave the entry guard the full circuit length). Circuits
/// longer than [`MAX_CIRCUIT_TTL`] hops are rejected at build time with
/// [`CircuitError::CircuitTooLongForTtl`]. Each peel validates
/// `1 <= ttl <= MAX_CIRCUIT_TTL` and drops on violation; real loop /
/// amplification is bounded by the cell-size shrinkage budget, not this field.
pub fn build_circuit(payload: &[u8], hops: &[Hop]) -> Result<Vec<u8>, CircuitError> {
    if hops.is_empty() {
        return Err(CircuitError::NoHops);
    }
    // Circuit-length cap: reject circuits longer than MAX_CIRCUIT_TTL hops. The
    // layer ttl itself is now a constant (M1 below), so this is a direct length
    // bound rather than a ttl-encoding limit; it keeps the existing ~15-hop
    // ceiling and the CircuitTooLongForTtl error.
    let outermost_ttl: u8 = (hops.len() as u8).saturating_add(1);
    if outermost_ttl > MAX_CIRCUIT_TTL {
        return Err(CircuitError::CircuitTooLongForTtl {
            hops: hops.len(),
            required: outermost_ttl,
            max: MAX_CIRCUIT_TTL,
        });
    }

    // CONSTANT per-layer TTL (audit cycle-4 M1): every layer carries the SAME
    // ttl. The old scheme set `ttl = hops.len - i + 1`, which leaked topology —
    // each relay, peeling its own layer, read `ttl - 2 = hops remaining
    // downstream`, and the entry guard read `ttl = N+1 = full circuit length`.
    // That is exactly the position/length onion routing must hide from
    // intermediate relays. A constant reveals nothing. Anti-loop is unaffected:
    // `peel_circuit` only validates `0 < ttl <= MAX_CIRCUIT_TTL` (it never
    // decrements), and real loop/amplification is bounded by the cell-size
    // shrinkage budget — the per-layer value never limited loop length anyway.
    let final_hop = hops.last().expect("hops non-empty");
    let mut inner = Vec::with_capacity(TTL_PREFIX_LEN + NEXT_HOP_ID_LEN + payload.len());
    let inner_ttl: u8 = MAX_CIRCUIT_TTL;
    inner.push(inner_ttl);
    inner.extend_from_slice(&FINAL_HOP_SENTINEL);
    inner.extend_from_slice(payload);
    let mut wrapped = onion::wrap_for_hop(&inner, &final_hop.pubkey);

    // Wrap through preceding hops in reverse order. Each layer's
    // plaintext = `[ttl(1)][next_hop_id(32)][previous_wrap]`, where
    // next_hop_id identifies the hop AFTER this one in forward direction
    // and ttl is the SAME constant on every layer (see M1 note above).
    for i in (0..hops.len() - 1).rev() {
        let this_hop = hops[i];
        let next_hop_in_chain = hops[i + 1];
        let layer_ttl: u8 = MAX_CIRCUIT_TTL;
        let mut layer = Vec::with_capacity(TTL_PREFIX_LEN + NEXT_HOP_ID_LEN + wrapped.len());
        layer.push(layer_ttl);
        layer.extend_from_slice(&next_hop_in_chain.node_id);
        layer.extend_from_slice(&wrapped);
        wrapped = onion::wrap_for_hop(&layer, &this_hop.pubkey);
    }
    Ok(wrapped)
}

/// Peel one layer at the current hop using its X25519 secret key.
/// Returns whether this hop should forward (and to whom) or it is
/// the final destination (with the recovered payload).
pub fn peel_circuit(
    envelope: &[u8],
    my_sk: &x25519_dalek::StaticSecret,
) -> Result<PeelResult, CircuitError> {
    let plaintext = onion::unwrap_at_hop(envelope, my_sk)?;
    // anti-loop TTL: layout is `[ttl(1)][next_hop_id(32)][inner]`.
    let min_len = TTL_PREFIX_LEN + NEXT_HOP_ID_LEN;
    if plaintext.len() < min_len {
        return Err(CircuitError::PlaintextTooShort {
            got: plaintext.len(),
            min: min_len,
        });
    }
    let ttl = plaintext[0];
    if ttl == 0 {
        return Err(CircuitError::TtlExhausted);
    }
    if ttl > MAX_CIRCUIT_TTL {
        return Err(CircuitError::TtlExceedsCap {
            got: ttl,
            max: MAX_CIRCUIT_TTL,
        });
    }
    let mut next_hop = [0u8; NEXT_HOP_ID_LEN];
    next_hop.copy_from_slice(&plaintext[TTL_PREFIX_LEN..TTL_PREFIX_LEN + NEXT_HOP_ID_LEN]);
    // wrap in Zeroizing
    // immediately so the bytes are wiped if the consumer drops
    // without forwarding (panic, channel closed, etc).
    let inner = zeroize::Zeroizing::new(plaintext[TTL_PREFIX_LEN + NEXT_HOP_ID_LEN..].to_vec());
    if next_hop == FINAL_HOP_SENTINEL {
        Ok(PeelResult::Final { payload: inner })
    } else {
        Ok(PeelResult::Forward { next_hop, inner })
    }
}

/// Per-layer wire overhead at the CIRCUIT level (TTL byte + next-hop-id
/// prefix + onion overhead). Caller computes max innermost payload from
/// this and the cell budget: for a 510 B cell and N-hop circuit, max
/// innermost payload ≈ `510 - PER_HOP_OVERHEAD * N + NEXT_HOP_ID_LEN +
/// TTL_PREFIX_LEN` (the FINAL hop's sentinel + ttl is part of innermost
/// data, not extra overhead).
///
/// added [`TTL_PREFIX_LEN`] = 1 to every layer; previous
/// callers that hard-coded the old value (32 + onion-overhead) need
/// to recompute their max-payload budgets — but the only caller
/// `packet.rs` reads this constant at runtime so the change propagates.
pub const PER_HOP_OVERHEAD: usize = TTL_PREFIX_LEN + NEXT_HOP_ID_LEN + onion::ONION_LAYER_OVERHEAD;

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;
    use x25519_dalek::{PublicKey as XPub, StaticSecret as XSec};

    fn fresh_hop_with_id(id_byte: u8) -> (XSec, Hop) {
        let sk = XSec::random_from_rng(OsRng);
        let pk = XPub::from(&sk).to_bytes();
        let mut node_id = [0u8; NEXT_HOP_ID_LEN];
        node_id[0] = id_byte; // distinct, non-zero, easy to grep in failures
        (
            sk,
            Hop {
                node_id,
                pubkey: pk,
            },
        )
    }

    #[test]
    fn epic482_1_build_circuit_rejects_zero_hops() {
        let err = build_circuit(b"data", &[]).unwrap_err();
        assert_eq!(err, CircuitError::NoHops);
    }

    #[test]
    fn epic482_1_single_hop_circuit_yields_final_at_only_hop() {
        // Degenerate 1-hop circuit: sender → hop1 (which is also the
        // destination). Useful as a primitive sanity check + as the
        // building block for a non-anonymity AEAD path that reuses
        // the same module.
        let (sk1, hop1) = fresh_hop_with_id(0xAA);
        let payload = b"single-hop direct message";
        let envelope = build_circuit(payload, &[hop1]).expect("build");

        let result = peel_circuit(&envelope, &sk1).expect("peel hop1");
        match result {
            PeelResult::Final { payload: p } => assert_eq!(p.as_slice(), payload),
            other => panic!("1-hop circuit must yield Final, got {other:?}"),
        }
    }

    #[test]
    fn epic482_1_three_hop_circuit_walks_through_all_hops() {
        // Canonical pattern: sender builds [hop1, hop2, hop3];
        // hop1 forwards to hop2; hop2 forwards to hop3; hop3 sees
        // the payload. Each hop sees ONLY the next-hop-id, never
        // the destination.
        let (sk1, hop1) = fresh_hop_with_id(0x01);
        let (sk2, hop2) = fresh_hop_with_id(0x02);
        let (sk3, hop3) = fresh_hop_with_id(0x03);

        let payload = b"this only hop3 sees";
        let envelope = build_circuit(payload, &[hop1, hop2, hop3]).expect("build");

        // Hop1: must say "Forward to hop2".
        let r1 = peel_circuit(&envelope, &sk1).expect("hop1 peel");
        let inner_for_hop2 = match r1 {
            PeelResult::Forward { next_hop, inner } => {
                assert_eq!(next_hop, hop2.node_id, "hop1 must forward to hop2");
                inner
            }
            other => panic!("hop1 must Forward, got {other:?}"),
        };

        // Hop2: must say "Forward to hop3".
        let r2 = peel_circuit(&inner_for_hop2, &sk2).expect("hop2 peel");
        let inner_for_hop3 = match r2 {
            PeelResult::Forward { next_hop, inner } => {
                assert_eq!(next_hop, hop3.node_id, "hop2 must forward to hop3");
                inner
            }
            other => panic!("hop2 must Forward, got {other:?}"),
        };

        // Hop3: must yield Final with the original payload.
        let r3 = peel_circuit(&inner_for_hop3, &sk3).expect("hop3 peel");
        match r3 {
            PeelResult::Final { payload: p } => assert_eq!(p.as_slice(), payload),
            other => panic!("hop3 must yield Final, got {other:?}"),
        }
    }

    #[test]
    fn epic482_1_intermediate_hop_cannot_see_payload_or_final_destination() {
        // Anonymity property: hop2 sees only that the message is from
        // hop1 (its session) and goes to hop3 next. It CANNOT see:
        // The original sender (already true via onion forward
        // secrecy — no shared identity in plaintext).
        // The final destination (hop4 in this 4-hop circuit).
        // The payload bytes.
        // This test asserts the negative directly: search hop2's
        // plaintext for the payload bytes + the final hop's id.
        let (sk2, hop2) = fresh_hop_with_id(0x20);
        let (_, hop3) = fresh_hop_with_id(0x30);
        let (_, hop4_final) = fresh_hop_with_id(0x40);

        let payload = b"FINAL_PAYLOAD_MARKER_xyz12345";

        // Walk hop1 → hop2 so we can inspect hop2's plaintext (its
        // forwarding-decision view). hop2's plaintext is what hop2
        // sees AFTER hop1 peels and forwards: anonymity requires the
        // payload + final-hop id NOT appear there.
        let (sk1_real, hop1_real) = fresh_hop_with_id(0x10);
        let envelope = build_circuit(payload, &[hop1_real, hop2, hop3, hop4_final])
            .expect("build with retained sk1");
        let to_hop2 = match peel_circuit(&envelope, &sk1_real).expect("hop1 peel") {
            PeelResult::Forward { inner, .. } => inner,
            other => panic!("hop1 must Forward, got {other:?}"),
        };
        // Now peel at hop2 — get hop2's plaintext (which is what
        // hop2 sees during its forwarding decision).
        let plaintext_at_hop2 = onion::unwrap_at_hop(&to_hop2, &sk2).expect("hop2 onion-unwrap");

        // hop2's plaintext = [hop3.node_id || hop3's onion envelope].
        // The hop3 envelope is opaque to hop2 (still encrypted under
        // hop3's key). Therefore the payload bytes + hop4's id MUST
        // NOT appear in plaintext_at_hop2.
        let needle_payload: &[u8] = payload;
        let needle_final_id: &[u8] = &hop4_final.node_id;
        assert!(
            plaintext_at_hop2
                .windows(needle_payload.len())
                .all(|w| w != needle_payload),
            "hop2 must NOT see payload bytes in its plaintext (onion broken)",
        );
        assert!(
            plaintext_at_hop2
                .windows(needle_final_id.len())
                .all(|w| w != needle_final_id),
            "hop2 must NOT see final hop's node_id in its plaintext (would let \
             hop2 identify the destination — onion broken)",
        );
    }

    #[test]
    fn epic482_1_per_hop_overhead_constant_matches_components() {
        assert_eq!(
            PER_HOP_OVERHEAD,
            TTL_PREFIX_LEN + NEXT_HOP_ID_LEN + onion::ONION_LAYER_OVERHEAD,
        );
        // 1 (ttl) + 32 (next-hop-id) + 60 (onion: 32 ephemeral + 12 nonce + 16 tag) = 93.
        assert_eq!(PER_HOP_OVERHEAD, 93);
    }

    #[test]
    fn epic482_1_envelope_size_grows_per_hop_count_as_expected() {
        // For payload P and N hops, envelope = P + 32 (final-hop
        // sentinel) + 60 (innermost onion) + (N-1) * 92 (PER_HOP)
        let (_, hop1) = fresh_hop_with_id(0x01);
        let (_, hop2) = fresh_hop_with_id(0x02);
        let (_, hop3) = fresh_hop_with_id(0x03);

        let payload = b"00000000"; // 8 bytes
        let env_1 = build_circuit(payload, &[hop1]).unwrap();
        let env_2 = build_circuit(payload, &[hop1, hop2]).unwrap();
        let env_3 = build_circuit(payload, &[hop1, hop2, hop3]).unwrap();

        // Each additional hop adds PER_HOP_OVERHEAD bytes.
        assert_eq!(env_2.len() - env_1.len(), PER_HOP_OVERHEAD);
        assert_eq!(env_3.len() - env_2.len(), PER_HOP_OVERHEAD);
    }

    #[test]
    fn epic482_1_wrong_hop_sk_at_intermediate_fails_loudly() {
        // If hop2 is offline and a different node tries to peel the
        // envelope hop1 forwarded, AEAD must fail — anonymity layer
        // does not leak "this is for someone else".
        let (sk1, hop1) = fresh_hop_with_id(0x01);
        let (_, hop2) = fresh_hop_with_id(0x02);
        let (sk_wrong, _hop_wrong) = fresh_hop_with_id(0xFF);
        let payload = b"data";

        let envelope = build_circuit(payload, &[hop1, hop2]).unwrap();
        let to_hop2 = match peel_circuit(&envelope, &sk1).unwrap() {
            PeelResult::Forward { inner, .. } => inner,
            other => panic!("hop1 must Forward, got {other:?}"),
        };

        // The wrong hop tries to peel hop2's envelope.
        let err = peel_circuit(&to_hop2, &sk_wrong).unwrap_err();
        assert!(
            matches!(err, CircuitError::Onion(OnionError::Aead)),
            "wrong hop must fail AEAD, not silently leak a forward decision: {err:?}"
        );
    }

    #[test]
    fn epic482_1_empty_payload_one_hop_works() {
        // 0-byte payload through 1 hop — minimum-size circuit.
        // Useful as a "ping" for circuit liveness.
        let (sk1, hop1) = fresh_hop_with_id(0xAA);
        let envelope = build_circuit(&[], &[hop1]).unwrap();
        match peel_circuit(&envelope, &sk1).unwrap() {
            PeelResult::Final { payload } => assert_eq!(payload.as_slice(), &[] as &[u8]),
            other => panic!("1-hop empty payload must yield Final, got {other:?}"),
        }
    }

    // ── anti-loop TTL ─────────────────────────────

    /// Honest 3-hop circuit produces ttl=4 outermost, decrementing to ttl=2
    /// at the final hop. All peels succeed.
    #[test]
    fn phase650_ttl_normal_3hop_circuit_succeeds() {
        let (sk1, hop1) = fresh_hop_with_id(0x01);
        let (sk2, hop2) = fresh_hop_with_id(0x02);
        let (sk3, hop3) = fresh_hop_with_id(0x03);
        let envelope = build_circuit(b"hello", &[hop1, hop2, hop3]).unwrap();
        let inner = match peel_circuit(&envelope, &sk1).unwrap() {
            PeelResult::Forward { next_hop, inner } => {
                assert_eq!(next_hop, hop2.node_id);
                inner
            }
            other => panic!("hop1 must Forward, got {other:?}"),
        };
        let inner = match peel_circuit(&inner, &sk2).unwrap() {
            PeelResult::Forward { next_hop, inner } => {
                assert_eq!(next_hop, hop3.node_id);
                inner
            }
            other => panic!("hop2 must Forward, got {other:?}"),
        };
        match peel_circuit(&inner, &sk3).unwrap() {
            PeelResult::Final { payload } => assert_eq!(payload.as_slice(), b"hello"),
            other => panic!("hop3 must Final, got {other:?}"),
        }
    }

    /// Reject a circuit longer than [`MAX_CIRCUIT_TTL`] - 1 hops at build
    /// time so an honest sender doesn't ship envelopes the receiver
    /// will silently drop.
    #[test]
    fn phase650_ttl_circuit_too_long_rejected_at_build() {
        // MAX_CIRCUIT_TTL = 16 ⇒ max hops = 15 (ttl outermost = 16).
        // 16 hops would require ttl=17 outermost, exceeding cap.
        let too_many: Vec<Hop> = (0..16).map(|i| fresh_hop_with_id(i as u8).1).collect();
        let err = build_circuit(b"x", &too_many).unwrap_err();
        assert!(
            matches!(err, CircuitError::CircuitTooLongForTtl { .. }),
            "{err:?}"
        );
    }

    /// Adversarial sender encodes ttl=0 in outermost layer. Receiver must
    /// drop the frame with TtlExhausted before processing the next-hop-id.
    #[test]
    fn phase650_ttl_zero_at_peel_drops_frame() {
        use crate::onion;
        let (sk1, hop1) = fresh_hop_with_id(0x01);
        // Hand-craft a layer plaintext with ttl=0. Bypass build_circuit
        // (which always sets ttl > 0) by manually wrapping.
        let mut malicious_inner = Vec::new();
        malicious_inner.push(0u8); // ttl=0 — adversarial
        malicious_inner.extend_from_slice(&FINAL_HOP_SENTINEL);
        malicious_inner.extend_from_slice(b"trying to amplify");
        let envelope = onion::wrap_for_hop(&malicious_inner, &hop1.pubkey);
        let err = peel_circuit(&envelope, &sk1).unwrap_err();
        assert!(matches!(err, CircuitError::TtlExhausted), "{err:?}");
    }

    /// Adversarial sender encodes ttl > MAX_CIRCUIT_TTL. Receiver must
    /// drop with TtlExceedsCap (a malicious sender attempting to inflate
    /// the per-circuit amplification budget beyond the configured cap).
    #[test]
    fn phase650_ttl_exceeds_cap_drops_frame() {
        use crate::onion;
        let (sk1, hop1) = fresh_hop_with_id(0x01);
        let mut malicious_inner = Vec::new();
        malicious_inner.push(MAX_CIRCUIT_TTL + 1); // honest senders never go this high
        malicious_inner.extend_from_slice(&FINAL_HOP_SENTINEL);
        malicious_inner.extend_from_slice(b"too tall");
        let envelope = onion::wrap_for_hop(&malicious_inner, &hop1.pubkey);
        let err = peel_circuit(&envelope, &sk1).unwrap_err();
        assert!(
            matches!(err, CircuitError::TtlExceedsCap { got, .. } if got == MAX_CIRCUIT_TTL + 1),
            "{err:?}"
        );
    }

    /// audit cycle-4 M1: the per-layer TTL must be a CONSTANT, so no relay can
    /// infer its position in the circuit (or the circuit length) from the TTL it
    /// peels. Read the raw leading TTL byte at every hop of a 4-hop circuit —
    /// entry, two middles, and final — and assert they are all identical.
    #[test]
    fn m1_ttl_is_constant_across_layers_no_position_leak() {
        use crate::onion;
        let (sk1, hop1) = fresh_hop_with_id(0x01);
        let (sk2, hop2) = fresh_hop_with_id(0x02);
        let (sk3, hop3) = fresh_hop_with_id(0x03);
        let (sk4, hop4) = fresh_hop_with_id(0x04);
        let envelope = build_circuit(b"payload", &[hop1, hop2, hop3, hop4]).unwrap();
        let body = TTL_PREFIX_LEN + NEXT_HOP_ID_LEN;

        let p1 = onion::unwrap_at_hop(&envelope, &sk1).unwrap();
        let p2 = onion::unwrap_at_hop(&p1[body..], &sk2).unwrap();
        let p3 = onion::unwrap_at_hop(&p2[body..], &sk3).unwrap();
        let p4 = onion::unwrap_at_hop(&p3[body..], &sk4).unwrap();

        assert_eq!(p1[0], MAX_CIRCUIT_TTL, "entry hop");
        assert_eq!(p2[0], MAX_CIRCUIT_TTL, "middle hop 1");
        assert_eq!(p3[0], MAX_CIRCUIT_TTL, "middle hop 2");
        assert_eq!(
            p4[0], MAX_CIRCUIT_TTL,
            "final hop TTL must equal the rest — no length leak"
        );
    }
}
