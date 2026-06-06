//! End-to-end anonymous packet.
//!
//! The user-facing API on top [`super::cell`] +
//! [`super::circuit`] + [`super::onion`]. Composes the three
//! primitives into "build a 512-byte cell that hops through N
//! relays and delivers a payload to the final destination".
//!
//! # Why a separate module on top of the primitives
//!
//! The load-bearing censorship-resistance property is **observer
//! sees uniform 512-byte cells at every hop**, including the
//! outbound from every relay. Without this:
//!
//! * Sender emits 512 B cell.
//! * Hop 1 peels one onion layer, produces a `[u8]` of size
//!   `(previous - 92)`. If hop 1 forwards those bytes RAW, the
//!   observer at the hop1→hop2 link sees a 420-byte payload.
//!   Hop 2 peels another layer, forwards 328 bytes. Hop 3 peels
//!   forwards 236 bytes. Cell sizes shrink monotonically along
//!   the circuit — that's a per-hop signal that immediately
//!   deanonymizes (observer infers hop position from cell size).
//!
//! [`peel_anonymous_cell`] guarantees the relay's outbound is also
//! a 512-byte cell by re-packing the peeled `inner` bytes through
//! [`super::cell::pack`]. The 92 bytes of overhead per layer
//! become zero-padding bytes inside the next cell, invisible to
//! observers and ignored by the next hop's `cell::unpack`.
//!
//! # Maximum user payload per hop count
//!
//! For an N-hop circuit packed into a 512-byte cell:
//!
//! max_payload(N) = MAX_PAYLOAD_PER_CELL - 92 * N
//! = 510 - 92 * N
//!
//! N=1 → 418 B
//! N=2 → 326 B
//! N=3 → 234 B
//! N=5 → 50 B
//! N=6 → reject — 510 - 552 < 0
//!
//! Higher hop counts trade payload budget for stronger
//! unlinkability. Real Tor uses 3 hops as the standard tradeoff;
//! we expose [`max_payload_for_hops`] so callers can pick.

use crate::cell::{self, CELL_SIZE, CellError, MAX_PAYLOAD_PER_CELL};
use crate::circuit::{self, CircuitError, Hop, NEXT_HOP_ID_LEN, PER_HOP_OVERHEAD, PeelResult};

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum PacketError {
    #[error("circuit: {0}")]
    Circuit(CircuitError),
    #[error("cell: {0}")]
    Cell(CellError),
    #[error("payload too large for {hops}-hop circuit: {got} B > {max} B")]
    PayloadTooLarge { hops: usize, got: usize, max: usize },
    #[error("hop count {got} exceeds max for cell budget (max ≈ {max})")]
    TooManyHops { got: usize, max: usize },
}

impl From<CircuitError> for PacketError {
    fn from(e: CircuitError) -> Self {
        Self::Circuit(e)
    }
}

impl From<CellError> for PacketError {
    fn from(e: CellError) -> Self {
        Self::Cell(e)
    }
}

/// Result of peeling one cell at the current hop. Critically
/// `Forward.outbound_cell` is ALREADY a 512-byte cell ready to send
/// — relays never see, expose, or transmit shorter buffers.
///
/// `Forward` carries a 544 B inline buffer (32 B next_hop + 512 B
/// cell) while `Final` carries a Vec<u8>; this is a "large enum
/// variant" lint trigger, but **the inline buffer is intentional**.
/// Boxing `Forward` would add an allocation per relay-hop on the
/// anonymity hot path (cell relay is the most-frequent operation
/// for relay nodes). The 520-byte size penalty matters only when
/// CellPeelResult sits in a long-lived collection — it doesn't;
/// callers consume it immediately.
#[derive(Debug, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum CellPeelResult {
    /// This hop forwards `outbound_cell` to `next_hop`.
    Forward {
        next_hop: [u8; NEXT_HOP_ID_LEN],
        outbound_cell: [u8; CELL_SIZE],
    },
    /// This hop is the destination — `payload` is the original message.
    /// wrapped in `Zeroizing` so
    /// the post-AEAD-decrypt plaintext is wiped from memory on drop
    /// (consumer typically forwards to app_registry which copies the
    /// bytes into its own delivery channel; once that copy is made
    /// the original is dropped here, taking the zeroize with it).
    Final {
        payload: zeroize::Zeroizing<Vec<u8>>,
    },
}

/// maximum hop count that fits
/// into a single 512-byte cell with zero user-payload bytes. Derived
/// [`MAX_PAYLOAD_PER_CELL`] / [`PER_HOP_OVERHEAD`]. Exposed as
/// a public constant so callers don't hardcode the magic `5`.
pub const MAX_HOPS_PER_CELL: usize = MAX_PAYLOAD_PER_CELL / PER_HOP_OVERHEAD;

/// Maximum user payload bytes for an N-hop circuit packed into a
/// 512-byte cell. Returns `None` when even 0 user bytes won't fit
/// (caller asked for more hops than the cell budget can carry).
///
/// This is the canonical helper for choosing `payload.len` ≤
/// `max_payload_for_hops(hops.len)` before calling
/// [`build_anonymous_cell`].
pub fn max_payload_for_hops(n: usize) -> Option<usize> {
    if n == 0 {
        return None; // 0 hops = nothing to encrypt for
    }
    MAX_PAYLOAD_PER_CELL.checked_sub(PER_HOP_OVERHEAD * n)
}

/// Build the outermost 512-byte cell for an N-hop circuit.
/// `hops[0]` is the FIRST relay (the cell's first transmission
/// goes to it); `hops[N-1]` is the FINAL destination that recovers
/// the payload.
pub fn build_anonymous_cell(payload: &[u8], hops: &[Hop]) -> Result<[u8; CELL_SIZE], PacketError> {
    let max = max_payload_for_hops(hops.len()).ok_or(PacketError::TooManyHops {
        got: hops.len(),
        // (510 - 32) / 92 = 5 hops max; show 5 as a friendly hint.
        max: MAX_PAYLOAD_PER_CELL / PER_HOP_OVERHEAD,
    })?;
    if payload.len() > max {
        return Err(PacketError::PayloadTooLarge {
            hops: hops.len(),
            got: payload.len(),
            max,
        });
    }
    let envelope = circuit::build_circuit(payload, hops)?;
    // Pack into a fixed-size cell. Cell padding fills the unused
    // bytes with zeros; observers see a uniform 512-byte cell.
    Ok(cell::pack(&envelope)?)
}

/// Peel one cell at the current hop using its X25519 secret key.
/// On `Forward`, the returned `outbound_cell` is also exactly 512
/// bytes — relay forwards as-is; observer cannot distinguish
/// from any other cell on the network by size.
pub fn peel_anonymous_cell(
    cell_bytes: &[u8; CELL_SIZE],
    my_sk: &x25519_dalek::StaticSecret,
) -> Result<CellPeelResult, PacketError> {
    let envelope = cell::unpack(cell_bytes)?;
    match circuit::peel_circuit(&envelope, my_sk)? {
        PeelResult::Forward { next_hop, inner } => {
            // Re-pack inner into a fresh cell so the outbound is
            // 512 bytes regardless of how many layers have been
            // peeled. This is the load-bearing anonymity property
            // that justifies this module existing on top of the
            // circuit primitive. `inner` derefs to `&Vec<u8>` →
            // `&[u8]` for `cell::pack`; the Zeroizing is dropped
            // immediately after pack so the inner plaintext is
            // wiped here at the relay and only the cell-level
            // ciphertext leaves this stack frame.
            let outbound_cell = cell::pack(&inner)?;
            Ok(CellPeelResult::Forward {
                next_hop,
                outbound_cell,
            })
        }
        PeelResult::Final { payload } => Ok(CellPeelResult::Final { payload }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;
    use x25519_dalek::{PublicKey as XPub, StaticSecret as XSec};

    fn fresh_hop(id_byte: u8) -> (XSec, Hop) {
        let sk = XSec::random_from_rng(OsRng);
        let pk = XPub::from(&sk).to_bytes();
        let mut node_id = [0u8; NEXT_HOP_ID_LEN];
        node_id[0] = id_byte;
        (
            sk,
            Hop {
                node_id,
                pubkey: pk,
            },
        )
    }

    #[test]
    fn epic482_1_max_payload_formula_matches_overhead() {
        // anti-loop TTL: PER_HOP_OVERHEAD bumped 92 → 93
        // (1 byte ttl per layer). Per-hop budgets shift by 1B × N:
        // 1 hop → 510 - 93 = 417
        // 2 hops → 510 - 186 = 324
        // 3 hops → 510 - 279 = 231
        assert_eq!(max_payload_for_hops(0), None, "0 hops is invalid");
        assert_eq!(max_payload_for_hops(1), Some(417));
        assert_eq!(max_payload_for_hops(2), Some(324));
        assert_eq!(max_payload_for_hops(3), Some(231));
        // Higher hop counts: at some N the formula goes negative.
        // (510 - 93*N < 0) when N >= 6.
        assert_eq!(
            max_payload_for_hops(6),
            None,
            "6 hops cannot fit in a 512 B cell"
        );
    }

    #[test]
    fn epic482_1_one_hop_round_trip() {
        let (sk1, hop1) = fresh_hop(0xAA);
        let payload = b"hello via 1-hop circuit";
        let cell = build_anonymous_cell(payload, &[hop1]).expect("build");
        assert_eq!(
            cell.len(),
            CELL_SIZE,
            "outbound MUST be cell-sized regardless of payload size"
        );

        match peel_anonymous_cell(&cell, &sk1).expect("peel") {
            CellPeelResult::Final { payload: p } => assert_eq!(p.as_slice(), payload),
            other => panic!("1-hop must yield Final, got {other:?}"),
        }
    }

    #[test]
    fn epic482_1_three_hop_end_to_end_each_outbound_is_cell_sized() {
        // The load-bearing test: walk a 3-hop circuit from sender
        // through hop1→hop2→hop3 and assert that EVERY transmission
        // observed on the wire is exactly CELL_SIZE bytes.
        let (sk1, hop1) = fresh_hop(0x01);
        let (sk2, hop2) = fresh_hop(0x02);
        let (sk3, hop3) = fresh_hop(0x03);

        let payload = b"only hop3 should see this";
        let sender_outbound = build_anonymous_cell(payload, &[hop1, hop2, hop3]).expect("build");
        assert_eq!(
            sender_outbound.len(),
            CELL_SIZE,
            "sender outbound must be cell-sized"
        );

        // Hop 1: peel + forward.
        let (next_hop_2, hop1_outbound) = match peel_anonymous_cell(&sender_outbound, &sk1).unwrap()
        {
            CellPeelResult::Forward {
                next_hop,
                outbound_cell,
            } => (next_hop, outbound_cell),
            other => panic!("hop1 must Forward, got {other:?}"),
        };
        assert_eq!(next_hop_2, hop2.node_id, "hop1 must forward to hop2");
        assert_eq!(
            hop1_outbound.len(),
            CELL_SIZE,
            "hop1 outbound must be cell-sized — the load-bearing anonymity invariant"
        );

        // Hop 2: peel + forward.
        let (next_hop_3, hop2_outbound) = match peel_anonymous_cell(&hop1_outbound, &sk2).unwrap() {
            CellPeelResult::Forward {
                next_hop,
                outbound_cell,
            } => (next_hop, outbound_cell),
            other => panic!("hop2 must Forward, got {other:?}"),
        };
        assert_eq!(next_hop_3, hop3.node_id, "hop2 must forward to hop3");
        assert_eq!(
            hop2_outbound.len(),
            CELL_SIZE,
            "hop2 outbound must be cell-sized"
        );

        // Hop 3: peel + Final.
        match peel_anonymous_cell(&hop2_outbound, &sk3).unwrap() {
            CellPeelResult::Final { payload: p } => assert_eq!(p.as_slice(), payload),
            other => panic!("hop3 must yield Final, got {other:?}"),
        }
    }

    #[test]
    fn epic482_1_observer_sees_uniform_cell_sizes_through_all_hops() {
        // The censorship-resistance property stated as a property
        // test: collect the byte-lengths of every transmission
        // observable on the wire (sender→hop1, hop1→hop2, hop2→hop3)
        // and assert they're all identical AND equal CELL_SIZE.
        let (sk1, hop1) = fresh_hop(0x11);
        let (sk2, hop2) = fresh_hop(0x22);
        let (sk3, hop3) = fresh_hop(0x33);

        let payload = b"observer sees uniform sizes";
        let mut wire_sizes: Vec<usize> = Vec::new();

        let c0 = build_anonymous_cell(payload, &[hop1, hop2, hop3]).unwrap();
        wire_sizes.push(c0.len());
        let c1 = match peel_anonymous_cell(&c0, &sk1).unwrap() {
            CellPeelResult::Forward { outbound_cell, .. } => outbound_cell,
            _ => unreachable!(),
        };
        wire_sizes.push(c1.len());
        let c2 = match peel_anonymous_cell(&c1, &sk2).unwrap() {
            CellPeelResult::Forward { outbound_cell, .. } => outbound_cell,
            _ => unreachable!(),
        };
        wire_sizes.push(c2.len());
        // Hop 3 is final — no further outbound, but we still observe
        // 3 cells on the wire (sender→hop1, hop1→hop2, hop2→hop3).
        let _ = peel_anonymous_cell(&c2, &sk3).unwrap();

        assert!(
            wire_sizes.iter().all(|&s| s == CELL_SIZE),
            "every transmission must be exactly {CELL_SIZE} bytes; \
             observed sizes: {wire_sizes:?}"
        );
        assert_eq!(
            wire_sizes.len(),
            3,
            "3-hop circuit produces 3 wire transmissions, observed {}",
            wire_sizes.len()
        );
    }

    #[test]
    fn epic482_1_observer_cannot_correlate_two_sends_of_same_payload() {
        // Anti-correlation: same payload + same hops, sent twice
        // produces distinct cells (because each onion layer uses a
        // fresh ephemeral X25519 key + random nonce). Without this
        // property an observer with sufficient logging could confirm
        // "this is the same message being resent".
        let (_, hop1) = fresh_hop(0x01);
        let (_, hop2) = fresh_hop(0x02);
        let (_, hop3) = fresh_hop(0x03);

        let payload = b"identical payload";
        let cell_a = build_anonymous_cell(payload, &[hop1, hop2, hop3]).unwrap();
        let cell_b = build_anonymous_cell(payload, &[hop1, hop2, hop3]).unwrap();
        assert_ne!(
            cell_a, cell_b,
            "two builds of the same payload through the same hops must \
             yield distinct cells (fresh ephemeral keys + random nonces)"
        );
    }

    #[test]
    fn epic482_1_max_size_payload_packs_to_exactly_cell_size() {
        // Boundary test: payload at MAX must produce a valid cell
        // (envelope == 510 B, cell == 512 B with 0 padding).
        let (sk1, hop1) = fresh_hop(0xAA);
        let max = max_payload_for_hops(1).unwrap();
        let payload = vec![0xCDu8; max];
        let cell = build_anonymous_cell(&payload, &[hop1]).unwrap();
        match peel_anonymous_cell(&cell, &sk1).unwrap() {
            CellPeelResult::Final { payload: p } => {
                assert_eq!(p.len(), max);
                assert_eq!(p.as_slice(), payload.as_slice());
            }
            other => panic!("expected Final, got {other:?}"),
        }
    }

    #[test]
    fn epic482_1_oversize_payload_rejected_at_build() {
        let (_, hop1) = fresh_hop(0xAA);
        let max = max_payload_for_hops(1).unwrap();
        let oversize = vec![0u8; max + 1];
        let err = build_anonymous_cell(&oversize, &[hop1]).unwrap_err();
        assert!(
            matches!(err, PacketError::PayloadTooLarge { .. }),
            "oversize payload must be rejected at build: {err:?}"
        );
    }

    #[test]
    fn epic482_1_too_many_hops_rejected_at_build() {
        let hops: Vec<_> = (0..6).map(|i| fresh_hop(i as u8 + 1).1).collect();
        let err = build_anonymous_cell(b"x", &hops).unwrap_err();
        assert!(
            matches!(err, PacketError::TooManyHops { .. }),
            "6+ hops cannot fit in a 512 B cell — must be rejected: {err:?}"
        );
    }

    #[test]
    fn epic482_1_zero_hops_rejected_at_build() {
        let err = build_anonymous_cell(b"x", &[]).unwrap_err();
        assert!(
            matches!(err, PacketError::TooManyHops { .. }),
            "0 hops is invalid (max_payload_for_hops returns None): {err:?}"
        );
    }

    #[test]
    fn epic482_1_wrong_hop_sk_fails_at_peel() {
        // A relay handed a cell intended for someone else cannot
        // decrypt it. Anonymity layer doesn't leak "this is for
        // someone else" — caller sees AEAD failure, no "wrong
        // recipient" oracle.
        let (_correct_sk, hop1) = fresh_hop(0x01);
        let (sk_wrong, _) = fresh_hop(0xFF);
        let cell = build_anonymous_cell(b"data", &[hop1]).unwrap();
        let err = peel_anonymous_cell(&cell, &sk_wrong).unwrap_err();
        // Wraps an OnionError::Aead through CircuitError.
        assert!(
            matches!(err, PacketError::Circuit(_)),
            "wrong hop must surface as Circuit error (wrapping Onion AEAD): {err:?}"
        );
    }

    #[test]
    fn epic482_1_padding_bytes_after_envelope_dont_affect_peel() {
        // A relay receiving a cell whose declared length is X and
        // padding zeros up to 512 must peel correctly: cell::unpack
        // returns Vec<u8> of length X (ignoring padding), then
        // circuit::peel_circuit sees only those X bytes.
        // This test exercises the cell-padding-invisible-to-circuit
        // contract (both modules ship together; future refactor
        // touching either must preserve this).
        let (sk1, hop1) = fresh_hop(0x01);
        let small_payload = b"tiny";
        let cell_bytes = build_anonymous_cell(small_payload, &[hop1]).unwrap();
        // Cell trailer should be many zero bytes (padding).
        assert!(
            cell_bytes[CELL_SIZE - 10..].iter().all(|&b| b == 0),
            "small payload must produce zero-padded cell trailer"
        );
        // Peel still recovers exactly the original payload.
        match peel_anonymous_cell(&cell_bytes, &sk1).unwrap() {
            CellPeelResult::Final { payload: p } => assert_eq!(p.as_slice(), small_payload),
            other => panic!("expected Final, got {other:?}"),
        }
    }

    // ── traffic-correlation on anonymity layer ────────────────────
    //
    // Threat model: an observer sits on BOTH the entry hop (sender →
    // relay 1) and the exit hop (relay 3 → receiver) of a 3-hop
    // circuit. Without padding, the observer can correlate flows by
    // SIZE — payload-of-100-bytes at entry will produce some matching
    // 100-byte (plus framing) sequence at exit. With cell padding
    // EVERY transmission on the circuit is exactly CELL_SIZE bytes
    // so size-based correlation is reduced to chance.
    //
    // Acceptance row: "< 10 % during padding". Below we
    // construct N=50 cells with strongly-varied payload sizes (1..= max)
    // and exercise three correlation modes:
    //
    // 1. Per-cell SIZE: every entry cell is 512 B regardless of
    // payload (already trivially proven by other tests; we
    // restate as the Shannon-entropy of the size distribution).
    //
    // 2. Cross-flow byte-content: post-AEAD entry bytes must be
    // indistinguishable from random; exit plaintexts can carry
    // structure (operator's actual messages have non-uniform
    // bytes). An entry-vs-exit byte-frequency CORRELATION
    // coefficient near 0 confirms the encryption layer broke
    // the byte-content link.
    //
    // 3. Brute-force byte-prefix matching: for every exit plaintext
    // observe its first M bytes, scan all N entry cells for any
    // that contains the same M-byte sub-sequence. Without
    // AEAD, prefix-match would succeed for the correct flow;
    // with AEAD, prefix-match success rate ≈ false-positive rate
    // from random-byte coincidence (≪ 10 %).

    /// Pearson correlation coefficient between two equal-length f64
    /// vectors. Returns 0.0 when either vector has zero variance.
    /// Used to compare byte-frequency histograms (256-element f64
    /// vectors normalised to sum=1).
    fn pearson_correlation(xs: &[f64], ys: &[f64]) -> f64 {
        assert_eq!(xs.len(), ys.len());
        let n = xs.len() as f64;
        let mx = xs.iter().sum::<f64>() / n;
        let my = ys.iter().sum::<f64>() / n;
        let mut num = 0.0;
        let mut dx2 = 0.0;
        let mut dy2 = 0.0;
        for (&x, &y) in xs.iter().zip(ys.iter()) {
            let dx = x - mx;
            let dy = y - my;
            num += dx * dy;
            dx2 += dx * dx;
            dy2 += dy * dy;
        }
        let denom = (dx2 * dy2).sqrt();
        if denom == 0.0 { 0.0 } else { num / denom }
    }

    fn byte_histogram_normalised(bytes: &[u8]) -> Vec<f64> {
        let mut counts = [0u64; 256];
        for &b in bytes {
            counts[b as usize] += 1;
        }
        let total = bytes.len() as f64;
        if total == 0.0 {
            return vec![0.0; 256];
        }
        counts.iter().map(|&c| c as f64 / total).collect()
    }

    /// every entry-side cell is exactly CELL_SIZE bytes
    /// regardless of the payload size used to construct it. Size-
    /// based correlation between sender (entry) and receiver (exit)
    /// observations is therefore ZERO — observer at entry sees only
    /// 512-byte uniformly-sized chunks.
    ///
    /// Restated as Shannon entropy of the per-cell size distribution:
    /// H(sizes) must equal 0.0 bits (single value 512 across all N).
    /// Acceptance bound for "< 10 %" correlation: H ≤ 0.5 bits — even
    /// at N=50 cells with one outlier this would barely register.
    #[test]
    fn epic485_3_size_distribution_is_collapsed_to_a_single_value() {
        let (_sk1, hop1) = fresh_hop(0x01);
        let (_sk2, hop2) = fresh_hop(0x02);
        let (_sk3, hop3) = fresh_hop(0x03);

        let max = max_payload_for_hops(3).unwrap(); // 234
        let mut entry_sizes: Vec<usize> = Vec::with_capacity(50);
        for i in 0..50 {
            // Vary payload size 1..=max in 50 steps.
            let n = 1 + (i * (max - 1)) / 49;
            let payload = vec![0xABu8; n];
            let cell = build_anonymous_cell(&payload, &[hop1, hop2, hop3]).unwrap();
            entry_sizes.push(cell.len());
        }

        // All 50 cells must be exactly CELL_SIZE.
        let unique: std::collections::HashSet<_> = entry_sizes.iter().copied().collect();
        assert_eq!(
            unique.len(),
            1,
            "entry cells must all have IDENTICAL size; got {unique:?} \
             distinct sizes — observer can correlate by size, breaking the < 10 % bound"
        );
        assert!(
            unique.contains(&CELL_SIZE),
            "the single observed size must equal CELL_SIZE = {CELL_SIZE}"
        );
    }

    /// byte-frequency histograms of entry-side cells
    /// (post-AEAD ciphertext) and exit-side plaintexts (post-peel)
    /// have ~zero Pearson correlation when plaintexts have biased
    /// content. A high correlation would mean AEAD encryption
    /// failed to mask plaintext structure → DPI could fingerprint
    /// the type of traffic flowing through the circuit.
    ///
    /// Test setup: construct N=50 cells whose plaintexts are biased
    /// ASCII text (non-uniform byte distribution). After AEAD layering
    /// the entry bytes should be uniformly random (high entropy). The
    /// EXIT plaintexts retain their original biased distribution.
    /// Pearson correlation between the two histograms ≈ 0.
    #[test]
    fn epic485_3_entry_exit_byte_histogram_correlation_below_10_pct() {
        let (sk1, hop1) = fresh_hop(0x01);
        let (sk2, hop2) = fresh_hop(0x02);
        let (sk3, hop3) = fresh_hop(0x03);

        // 50 plaintexts of ASCII repeating "anti-correlation-witness "
        // — strongly biased byte distribution (only ~25 distinct bytes
        // out of 256, heavy weight on space + lower-case ASCII).
        let max = max_payload_for_hops(3).unwrap();
        let pattern = b"anti-correlation-witness "; // 26 bytes
        let mut entry_bytes_concat: Vec<u8> = Vec::new();
        let mut exit_plaintexts_concat: Vec<u8> = Vec::new();

        for i in 0..50 {
            let n = 16 + (i % (max - 16));
            let mut plaintext = Vec::with_capacity(n);
            while plaintext.len() < n {
                let take = (n - plaintext.len()).min(pattern.len());
                plaintext.extend_from_slice(&pattern[..take]);
            }
            // Build cell, peel through 3 hops, recover plaintext.
            let entry_cell = build_anonymous_cell(&plaintext, &[hop1, hop2, hop3]).unwrap();
            entry_bytes_concat.extend_from_slice(&entry_cell);

            let after_h1 = match peel_anonymous_cell(&entry_cell, &sk1).unwrap() {
                CellPeelResult::Forward { outbound_cell, .. } => outbound_cell,
                _ => unreachable!(),
            };
            let after_h2 = match peel_anonymous_cell(&after_h1, &sk2).unwrap() {
                CellPeelResult::Forward { outbound_cell, .. } => outbound_cell,
                _ => unreachable!(),
            };
            match peel_anonymous_cell(&after_h2, &sk3).unwrap() {
                CellPeelResult::Final { payload: p } => {
                    assert_eq!(p.as_slice(), plaintext.as_slice(), "round-trip integrity");
                    exit_plaintexts_concat.extend_from_slice(&p);
                }
                _ => unreachable!(),
            }
        }

        // Compute byte histograms and Pearson correlation.
        let entry_hist = byte_histogram_normalised(&entry_bytes_concat);
        let exit_hist = byte_histogram_normalised(&exit_plaintexts_concat);
        let corr = pearson_correlation(&entry_hist, &exit_hist).abs();

        // Spec bound: < 10 % correlation under padding. We use
        // |Pearson coefficient| because correlation can be negative.
        assert!(
            corr < 0.10,
            "entry/exit byte-histogram |Pearson| = {corr:.4} ≥ 0.10 — \
             AEAD encryption is leaking plaintext structure"
        );

        // Negative-control: directly correlate exit_plaintexts with
        // itself. Should be 1.0 (or very close). Proves the
        // correlation function has signal.
        let self_corr = pearson_correlation(&exit_hist, &exit_hist);
        assert!(
            (self_corr - 1.0).abs() < 1e-9,
            "self-correlation should be 1.0; got {self_corr}"
        );
    }

    /// brute-force prefix matching — for each exit plaintext
    /// take the first M=8 bytes; scan all N entry cells for a substring
    /// match. Acceptance: success-rate over false-positive baseline
    /// (chance match) below 10 %.
    ///
    /// With AEAD, the entry-side ciphertext is uniformly random — the
    /// probability that any specific 8-byte sequence from a plaintext
    /// appears verbatim inside a 512-byte random cell is bounded
    /// by (512 - 7) × 256^-8 ≈ 5.5 × 10^-17 — ESSENTIALLY ZERO. So
    /// success rate must be 0/N in this test.
    #[test]
    fn epic485_3_prefix_matching_attack_fails_post_aead() {
        let (sk1, hop1) = fresh_hop(0x01);
        let (sk2, hop2) = fresh_hop(0x02);
        let (sk3, hop3) = fresh_hop(0x03);

        let max = max_payload_for_hops(3).unwrap();
        let mut entries: Vec<[u8; CELL_SIZE]> = Vec::new();
        let mut exit_prefixes: Vec<[u8; 8]> = Vec::new();

        for i in 0..50 {
            // Each plaintext starts with a unique 8-byte marker so
            // collisions across flows can't muddy the result.
            let mut plaintext = Vec::with_capacity(max);
            plaintext.extend_from_slice(&(0x4242_4242_4242_0000_u64 + i as u64).to_be_bytes());
            // Pad to a varying length so we exercise the size-collapse
            // property too.
            let pad_len = (i * 4) % (max - 8);
            plaintext.extend(std::iter::repeat_n(0xCDu8, pad_len));

            let entry_cell = build_anonymous_cell(&plaintext, &[hop1, hop2, hop3]).unwrap();
            entries.push(entry_cell);

            // Peel and collect exit prefix.
            let after_h1 = match peel_anonymous_cell(&entry_cell, &sk1).unwrap() {
                CellPeelResult::Forward { outbound_cell, .. } => outbound_cell,
                _ => unreachable!(),
            };
            let after_h2 = match peel_anonymous_cell(&after_h1, &sk2).unwrap() {
                CellPeelResult::Forward { outbound_cell, .. } => outbound_cell,
                _ => unreachable!(),
            };
            let plain = match peel_anonymous_cell(&after_h2, &sk3).unwrap() {
                CellPeelResult::Final { payload: p } => p,
                _ => unreachable!(),
            };
            let mut prefix = [0u8; 8];
            prefix.copy_from_slice(&plain[..8]);
            exit_prefixes.push(prefix);
        }

        // For each exit prefix, count how many entry cells contain
        // the prefix as a sub-sequence.
        let mut total_matches = 0usize;
        for prefix in &exit_prefixes {
            for entry in &entries {
                if entry.windows(8).any(|w| w == &prefix[..]) {
                    total_matches += 1;
                }
            }
        }

        let attempts = exit_prefixes.len() * entries.len(); // 50 × 50 = 2500
        let success_rate = total_matches as f64 / attempts as f64;
        assert!(
            success_rate < 0.10,
            "prefix-matching attack succeeded at {:.2} % \
             (≥ 10 % spec bound); AEAD is not masking plaintext prefixes — \
             total_matches = {total_matches} of {attempts} attempts",
            success_rate * 100.0
        );

        // Sanity check: at least one entry cell SHOULD contain its OWN
        // peel-result as a substring if AEAD were broken (exit plaintext
        // == sub-slice of entry ciphertext). We expect zero — and the
        // assert above passing with success_rate ≈ 0 confirms it.
        // Negative control to prove the matcher works: an entry cell
        // that LITERALLY contains a known prefix in its bytes should
        // be detected.
        let known_prefix = b"\x4Bb\x4Bb\x4Bb\x4B!"; // distinct from any real prefix
        let mut synthetic = [0u8; CELL_SIZE];
        synthetic[100..108].copy_from_slice(known_prefix);
        assert!(
            synthetic.windows(8).any(|w| w == known_prefix),
            "matcher must detect known prefix in synthetic entry — \
             test sanity check, would only fail if `windows` semantics changed"
        );
    }
}
