//! Stateful-circuit BUILD — single-pass per-hop key install (onion-registration
//! epic b2; Epic 482.7 sub-problem A, "Option B1"). See
//! `docs/internal/PLAN_ANON_SERVICE_ONION_REGISTRATION.md` §3.A +
//! `PLAN_STATEFUL_CIRCUITS_482_7.md` §3.
//!
//! The setup message is an onion envelope built exactly like
//! [`crate::circuit::build_circuit`], but each hop's layer additionally carries
//! a small **install instruction**: the circuit ids this hop maps between, and a
//! sender-chosen symmetric `circuit_key` the data plane (b3) reuses so data
//! cells need no per-message ECDH.
//!
//! ## Crypto reuse (why this is low-risk)
//! Each layer is sealed with the existing, audited per-hop primitive
//! ([`crate::onion::wrap_for_hop`] / [`unwrap_at_hop`]). This module does NOT
//! introduce new sealing — it only defines the PLAINTEXT layout inside each
//! onion layer. So a hop's install bytes are readable only by that hop (its
//! layer is encrypted to its X25519 key); a compromised relay learns ITS OWN
//! circuit key, never another hop's.
//!
//! ## Known property (Option B1, documented tradeoff)
//! `circuit_key` is sender-chosen and reused for the circuit's lifetime → NO
//! per-circuit forward secrecy and a longer-lived correlatable key. This is the
//! deliberate amortisation tradeoff; it is bounded by circuit ROTATION (b6 /
//! 482.7 §4.5), not by this module. b2 ships only the build/peel framing.

use zeroize::Zeroizing;

use crate::circuit::{CircuitError, FINAL_HOP_SENTINEL, MAX_CIRCUIT_TTL, NEXT_HOP_ID_LEN};
use crate::circuit_data::CircuitCellBytes;
use crate::circuit_wire::CircuitId;
use crate::onion;

/// Length of a `CircuitId` on the wire.
const CID_LEN: usize = 4;
/// Length of the installed symmetric circuit key.
pub const CIRCUIT_KEY_LEN: usize = 32;
/// TTL byte (anti-loop, constant per layer — same rationale as `circuit.rs`).
const TTL_LEN: usize = 1;
/// Width of the negotiated data-cell size on the wire (u16 BE).
const CELL_BYTES_LEN: usize = 2;

/// Fixed per-layer prefix BEFORE the inner ciphertext:
/// `[ttl(1)][next_hop_id(32)][circuit_id_in(4)][circuit_id_out(4)][circuit_key(32)][cell_bytes(2)]`.
///
/// `cell_bytes` is the SAME number in every layer — it is a property of the
/// circuit, not of the hop (see [`build_circuit_setup`], which takes it once so
/// the hops cannot be given differing values). Each hop learns it here and then
/// refuses every data cell of any other size, which is what makes the size
/// uniform where uniformity actually protects anything: within one circuit,
/// against the hop that sees all of its cells.
const SETUP_PREFIX_LEN: usize =
    TTL_LEN + NEXT_HOP_ID_LEN + CID_LEN + CID_LEN + CIRCUIT_KEY_LEN + CELL_BYTES_LEN;

/// One hop in a circuit-setup, with its install parameters. `circuit_id_in` is
/// the id cells arriving from the PREVIOUS link will carry; `circuit_id_out` is
/// the id this hop stamps on cells it forwards to the next link (so the next
/// hop's `circuit_id_in` == this hop's `circuit_id_out`). `circuit_key` is the
/// symmetric key the data plane reuses for this hop's layer.
#[derive(Clone)]
pub struct CircuitSetupHop {
    pub node_id: [u8; NEXT_HOP_ID_LEN],
    pub pubkey: [u8; 32],
    pub circuit_id_in: CircuitId,
    pub circuit_id_out: CircuitId,
    pub circuit_key: [u8; CIRCUIT_KEY_LEN],
}

/// What a hop installs after peeling its setup layer: a mapping
/// `(prev_link, circuit_id_in) → (next_link, circuit_id_out, circuit_key)`.
/// `prev_link` is known from the frame's authenticated sender; `next_link` is
/// `next_hop` (forward case) or none (terminus).
#[derive(Clone, PartialEq, Eq)]
pub struct CircuitInstall {
    pub circuit_id_in: CircuitId,
    pub circuit_id_out: CircuitId,
    pub circuit_key: [u8; CIRCUIT_KEY_LEN],
    /// Size of every data cell on this circuit, chosen by the originator.
    pub cell_bytes: CircuitCellBytes,
}

impl Drop for CircuitInstall {
    fn drop(&mut self) {
        // diff-audit Δ2-j: scrub key material on drop.
        use zeroize::Zeroize;
        self.circuit_key.zeroize();
    }
}

impl Drop for CircuitSetupHop {
    fn drop(&mut self) {
        // diff-audit Δ2-j: scrub key material on drop.
        use zeroize::Zeroize;
        self.circuit_key.zeroize();
    }
}

impl std::fmt::Debug for CircuitInstall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the key material.
        f.debug_struct("CircuitInstall")
            .field("circuit_id_in", &self.circuit_id_in)
            .field("circuit_id_out", &self.circuit_id_out)
            .field("circuit_key", &"<redacted>")
            .field("cell_bytes", &self.cell_bytes.get())
            .finish()
    }
}

/// Result of peeling one setup layer.
#[derive(Debug)]
pub enum SetupPeelResult {
    /// Intermediate hop: install the mapping, then forward `inner` (a
    /// `CircuitBuild` cell) to `next_hop`.
    Forward {
        install: CircuitInstall,
        next_hop: [u8; NEXT_HOP_ID_LEN],
        inner: Zeroizing<Vec<u8>>,
    },
    /// Circuit terminus: install the mapping (so it can drive the return path);
    /// `payload` is any piggy-backed terminus message (e.g. registration, b4).
    Terminus {
        install: CircuitInstall,
        payload: Zeroizing<Vec<u8>>,
    },
}

/// Build a circuit-setup envelope. `hops[0]` is the first hop; `hops[N-1]` is
/// the terminus (e.g. the rendezvous relay R). `terminus_payload` is delivered
/// (decrypted) to the terminus alongside its install (may be empty).
pub fn build_circuit_setup(
    hops: &[CircuitSetupHop],
    cell: CircuitCellBytes,
    terminus_payload: &[u8],
) -> Result<Vec<u8>, CircuitError> {
    if hops.is_empty() {
        return Err(CircuitError::NoHops);
    }
    let outermost_ttl = (hops.len() as u8).saturating_add(1);
    if outermost_ttl > MAX_CIRCUIT_TTL {
        return Err(CircuitError::CircuitTooLongForTtl {
            hops: hops.len(),
            required: outermost_ttl,
            max: MAX_CIRCUIT_TTL,
        });
    }

    // Innermost layer = terminus: next_hop = sentinel, inner = terminus_payload.
    let last = hops.last().expect("non-empty");
    let inner = build_layer(&FINAL_HOP_SENTINEL, last, cell, terminus_payload);
    let mut wrapped = onion::wrap_for_hop(&inner, &last.pubkey);

    // Wrap through preceding hops in reverse; each layer carries THIS hop's
    // install + next_hop_id pointing at the following hop.
    for i in (0..hops.len() - 1).rev() {
        let this_hop = &hops[i];
        let next_node_id = hops[i + 1].node_id;
        let layer = build_layer(&next_node_id, this_hop, cell, &wrapped);
        wrapped = onion::wrap_for_hop(&layer, &this_hop.pubkey);
    }
    Ok(wrapped)
}

/// Assemble one setup layer plaintext (constant TTL, anti-topology-leak — see
/// `circuit.rs` M1 note).
fn build_layer(
    next_hop_id: &[u8; NEXT_HOP_ID_LEN],
    hop: &CircuitSetupHop,
    cell: CircuitCellBytes,
    inner: &[u8],
) -> Vec<u8> {
    let mut layer = Vec::with_capacity(SETUP_PREFIX_LEN + inner.len());
    layer.push(MAX_CIRCUIT_TTL);
    layer.extend_from_slice(next_hop_id);
    layer.extend_from_slice(&hop.circuit_id_in.to_be_bytes());
    layer.extend_from_slice(&hop.circuit_id_out.to_be_bytes());
    layer.extend_from_slice(&hop.circuit_key);
    layer.extend_from_slice(&(cell.get() as u16).to_be_bytes());
    layer.extend_from_slice(inner);
    layer
}

/// Peel one setup layer at the current hop using its X25519 secret key. Returns
/// the install mapping plus where to forward (or terminus + payload).
pub fn peel_circuit_setup(
    envelope: &[u8],
    my_sk: &x25519_dalek::StaticSecret,
) -> Result<SetupPeelResult, CircuitError> {
    let plaintext = Zeroizing::new(onion::unwrap_at_hop(envelope, my_sk)?);
    if plaintext.len() < SETUP_PREFIX_LEN {
        return Err(CircuitError::PlaintextTooShort {
            got: plaintext.len(),
            min: SETUP_PREFIX_LEN,
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
    let mut o = TTL_LEN;
    let mut next_hop = [0u8; NEXT_HOP_ID_LEN];
    next_hop.copy_from_slice(&plaintext[o..o + NEXT_HOP_ID_LEN]);
    o += NEXT_HOP_ID_LEN;
    let circuit_id_in = read_cid(&plaintext, o);
    o += CID_LEN;
    let circuit_id_out = read_cid(&plaintext, o);
    o += CID_LEN;
    let mut circuit_key = [0u8; CIRCUIT_KEY_LEN];
    circuit_key.copy_from_slice(&plaintext[o..o + CIRCUIT_KEY_LEN]);
    o += CIRCUIT_KEY_LEN;
    // A size outside the legal range is a malformed setup, not a circuit to
    // install: the hop would accept cells it can never frame a payload into.
    let cell_bytes =
        CircuitCellBytes::new(u16::from_be_bytes([plaintext[o], plaintext[o + 1]]) as usize)?;
    o += CELL_BYTES_LEN;
    let inner = Zeroizing::new(plaintext[o..].to_vec());

    let install = CircuitInstall {
        circuit_id_in,
        circuit_id_out,
        circuit_key,
        cell_bytes,
    };
    if next_hop == FINAL_HOP_SENTINEL {
        Ok(SetupPeelResult::Terminus {
            install,
            payload: inner,
        })
    } else {
        Ok(SetupPeelResult::Forward {
            install,
            next_hop,
            inner,
        })
    }
}

fn read_cid(buf: &[u8], at: usize) -> CircuitId {
    u32::from_be_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit_data::MIN_CIRCUIT_CELL_BYTES;
    use rand_core::OsRng;
    use x25519_dalek::{PublicKey, StaticSecret};

    fn hop(i: u8, cid_in: u32, cid_out: u32) -> (StaticSecret, CircuitSetupHop) {
        let sk = StaticSecret::random_from_rng(OsRng);
        let pk = PublicKey::from(&sk).to_bytes();
        let h = CircuitSetupHop {
            node_id: [i; NEXT_HOP_ID_LEN],
            pubkey: pk,
            circuit_id_in: cid_in,
            circuit_id_out: cid_out,
            circuit_key: [i ^ 0x5A; CIRCUIT_KEY_LEN],
        };
        (sk, h)
    }

    #[test]
    fn three_hop_setup_installs_each_hop_and_reaches_terminus() {
        // Chain: h0 → h1 → h2(terminus). Per-link ids: in/out chained so
        // h_i.out == h_{i+1}.in.
        let (sk0, h0) = hop(0, 10, 11);
        let (sk1, h1) = hop(1, 11, 12);
        let (sk2, h2) = hop(2, 12, 0);
        let hops = [h0.clone(), h1.clone(), h2.clone()];

        let env = build_circuit_setup(&hops, CircuitCellBytes::legacy(), b"register-me").unwrap();

        // Hop 0 peels → installs (10→11), forwards to node_id [1;32].
        let r0 = peel_circuit_setup(&env, &sk0).unwrap();
        let inner0 = match r0 {
            SetupPeelResult::Forward {
                install,
                next_hop,
                inner,
            } => {
                assert_eq!(install.circuit_id_in, 10);
                assert_eq!(install.circuit_id_out, 11);
                assert_eq!(install.circuit_key, h0.circuit_key);
                assert_eq!(next_hop, [1u8; NEXT_HOP_ID_LEN]);
                inner
            }
            other => panic!("hop0 expected Forward, got {other:?}"),
        };

        // Hop 1 peels inner0 → installs (11→12), forwards to [2;32].
        let r1 = peel_circuit_setup(&inner0, &sk1).unwrap();
        let inner1 = match r1 {
            SetupPeelResult::Forward {
                install,
                next_hop,
                inner,
            } => {
                assert_eq!(install.circuit_id_in, 11);
                assert_eq!(install.circuit_id_out, 12);
                assert_eq!(next_hop, [2u8; NEXT_HOP_ID_LEN]);
                inner
            }
            other => panic!("hop1 expected Forward, got {other:?}"),
        };

        // Hop 2 = terminus: installs (12→0), recovers the piggy-backed payload.
        match peel_circuit_setup(&inner1, &sk2).unwrap() {
            SetupPeelResult::Terminus { install, payload } => {
                assert_eq!(install.circuit_id_in, 12);
                assert_eq!(install.circuit_key, h2.circuit_key);
                assert_eq!(&*payload, b"register-me");
            }
            other => panic!("hop2 expected Terminus, got {other:?}"),
        }
    }

    #[test]
    fn single_hop_setup_is_terminus() {
        let (sk0, h0) = hop(0, 7, 0);
        let env = build_circuit_setup(&[h0], CircuitCellBytes::legacy(), b"").unwrap();
        match peel_circuit_setup(&env, &sk0).unwrap() {
            SetupPeelResult::Terminus { install, payload } => {
                assert_eq!(install.circuit_id_in, 7);
                assert!(payload.is_empty());
            }
            other => panic!("expected Terminus, got {other:?}"),
        }
    }

    #[test]
    fn wrong_key_fails_to_peel() {
        let (_sk0, h0) = hop(0, 1, 2);
        let (sk_other, _) = hop(9, 0, 0);
        let env = build_circuit_setup(&[h0], CircuitCellBytes::legacy(), b"x").unwrap();
        assert!(peel_circuit_setup(&env, &sk_other).is_err());
    }

    #[test]
    fn rejects_empty_hops() {
        assert!(matches!(
            build_circuit_setup(&[], CircuitCellBytes::legacy(), b""),
            Err(CircuitError::NoHops)
        ));
    }

    /// Every hop of one circuit must learn the SAME cell size. If they ever
    /// disagreed, a middle hop would drop each cell as wrong-sized and the
    /// circuit would go silently dead — so the size is taken once, for the
    /// circuit, and this asserts it lands identically at all three hops.
    ///
    /// Break-check: make `build_layer` write `CircuitCellBytes::legacy()`
    /// instead of `cell` and this goes red at hop 0.
    #[test]
    fn one_size_reaches_every_hop_of_the_circuit() {
        let (sk0, h0) = hop(0, 10, 11);
        let (sk1, h1) = hop(1, 11, 12);
        let (sk2, h2) = hop(2, 12, 0);
        let chosen = CircuitCellBytes::new(4096).unwrap();

        let env = build_circuit_setup(&[h0, h1, h2], chosen, b"payload").unwrap();

        let inner0 = match peel_circuit_setup(&env, &sk0).unwrap() {
            SetupPeelResult::Forward { install, inner, .. } => {
                assert_eq!(install.cell_bytes, chosen, "hop 0");
                inner
            }
            other => panic!("hop0 expected Forward, got {other:?}"),
        };
        let inner1 = match peel_circuit_setup(&inner0, &sk1).unwrap() {
            SetupPeelResult::Forward { install, inner, .. } => {
                assert_eq!(install.cell_bytes, chosen, "hop 1");
                inner
            }
            other => panic!("hop1 expected Forward, got {other:?}"),
        };
        match peel_circuit_setup(&inner1, &sk2).unwrap() {
            SetupPeelResult::Terminus { install, .. } => {
                assert_eq!(install.cell_bytes, chosen, "terminus");
            }
            other => panic!("hop2 expected Terminus, got {other:?}"),
        }
    }

    /// A setup naming a size no circuit may use is refused outright. Installing
    /// it would give the hop a circuit it can never frame a payload into (below
    /// the floor) or one that overruns the u16 length field (above the cap).
    ///
    /// The layer is built by hand because `build_circuit_setup` cannot express
    /// an illegal size — `CircuitCellBytes` will not hold one.
    #[test]
    fn a_setup_naming_an_illegal_cell_size_is_refused() {
        for bad in [0u16, 1, (MIN_CIRCUIT_CELL_BYTES - 1) as u16] {
            let sk = StaticSecret::random_from_rng(OsRng);
            let pk = PublicKey::from(&sk).to_bytes();
            let mut layer = Vec::new();
            layer.push(MAX_CIRCUIT_TTL);
            layer.extend_from_slice(&FINAL_HOP_SENTINEL);
            layer.extend_from_slice(&7u32.to_be_bytes());
            layer.extend_from_slice(&0u32.to_be_bytes());
            layer.extend_from_slice(&[0x11u8; CIRCUIT_KEY_LEN]);
            layer.extend_from_slice(&bad.to_be_bytes());
            let env = onion::wrap_for_hop(&layer, &pk);

            assert!(
                peel_circuit_setup(&env, &sk).is_err(),
                "cell size {bad} must not install a circuit"
            );
        }
    }

    #[test]
    fn rejects_too_long() {
        let many: Vec<CircuitSetupHop> = (0..MAX_CIRCUIT_TTL).map(|i| hop(i, 0, 0).1).collect();
        assert!(matches!(
            build_circuit_setup(&many, CircuitCellBytes::legacy(), b""),
            Err(CircuitError::CircuitTooLongForTtl { .. })
        ));
    }
}
