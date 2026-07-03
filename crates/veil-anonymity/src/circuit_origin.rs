//! Origin-side circuit state (onion-registration epic b5a) — the view held by
//! the node that BUILT a circuit (the location-anonymous service / receiver),
//! as opposed to the relays it passes through (`circuit_table`). See
//! `docs/internal/PLAN_ANON_SERVICE_ONION_REGISTRATION.md` §3.D.
//!
//! The originator assigns every link's `circuit_id` and every hop's
//! `circuit_key`, builds the setup envelope (b2), and keeps the ordered keys so
//! it can OPEN return cells (b3): an introduce that R forwards down the circuit
//! arrives at the originator wrapped in N accreted layers, which it peels with
//! `[k0 … k_terminus]`. The relay path never learns the originator — this is the
//! state that makes the originator able to receive without exposing its address.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use rand_core::{OsRng, RngCore};

use crate::circuit::CircuitError;
use crate::circuit_data::{Direction, apply_layers, read_payload};
use crate::circuit_setup::{CIRCUIT_KEY_LEN, CircuitSetupHop, build_circuit_setup};
use crate::circuit_wire::CircuitId;

type Link = [u8; 32];

/// One hop the originator routes through: its id + X25519 public key.
#[derive(Clone, Copy, Debug)]
pub struct OriginHop {
    pub node_id: Link,
    pub pubkey: [u8; 32],
}

/// The originator's record of a circuit it built. Holds the per-hop keys
/// (first-hop → terminus order) needed to open return cells.
#[derive(Clone)]
pub struct OriginCircuit {
    /// Circuit keys in first-hop → terminus order (the open order for returns).
    pub circuit_keys: Vec<[u8; CIRCUIT_KEY_LEN]>,
    /// First hop's node_id — return cells arrive from here.
    pub first_hop: Link,
    /// Circuit id on the originator↔first-hop link — return cells carry it.
    pub origin_circuit_id: CircuitId,
    /// Build time (unix secs) for idle GC / rotation.
    pub created_unix: u64,
    /// Establishment confirmation (diff-audit Δ2-d): set when the terminus's
    /// `CircuitBuilt` ACK reaches the originator, proving the whole path is up.
    /// `Arc<AtomicBool>` so it survives the table's `Arc<OriginCircuit>` sharing.
    /// `false` until the ACK arrives — the maintenance tick re-selects an
    /// unconfirmed path rather than rebuilding a possibly-dead frozen one.
    pub confirmed: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// True when this is an EPHEMERAL REPLY circuit (built per outgoing send to
    /// carry the recipient's answer back). An introduce arriving down a reply
    /// circuit is the recipient ANSWERING something we sent live — the one
    /// signal that proves OUR OWN live introduce reached them (a generic
    /// verified inbound only proves them→us). The sender-side stall detector
    /// keys off this. False for hosted-service / data circuits.
    pub is_reply: bool,
}

impl Drop for OriginCircuit {
    fn drop(&mut self) {
        // diff-audit (zeroize sweep follow-up): scrub the per-hop symmetric
        // keys on drop. This is the originator's copy of EVERY hop key for a
        // circuit it built (used to open every return cell) — the highest-value
        // data-plane key material — and it was the one spot the Δ2-j sweep
        // missed (the relay-side `CircuitState` and `CircuitInstall` already
        // zeroize on drop). `#[derive(Clone)]` is retained; each clone scrubs
        // its own copy here.
        use zeroize::Zeroize;
        self.circuit_keys.zeroize();
    }
}

impl OriginCircuit {
    /// Mark the circuit confirmed (its `CircuitBuilt` ACK arrived).
    pub fn mark_confirmed(&self) {
        self.confirmed
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// Whether the establishment ACK has been seen.
    pub fn is_confirmed(&self) -> bool {
        self.confirmed.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Open a return cell (introduce forwarded down the circuit): apply ALL N
    /// circuit-key layers (XOR, fixed-size) then read the framed payload back
    /// out. The result is the inner payload the terminus sent (e.g. a sealed
    /// introduce to decrypt next).
    pub fn open_return(&self, seq: u32, cell: &[u8]) -> Result<Vec<u8>, CircuitError> {
        let mut buf = cell.to_vec();
        apply_layers(&self.circuit_keys, Direction::Return, seq, &mut buf)?;
        read_payload(&buf)
            .ok_or_else(|| CircuitError::Malformed("circuit return payload framing".into()))
    }
}

impl std::fmt::Debug for OriginCircuit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OriginCircuit")
            .field("hops", &self.circuit_keys.len())
            .field("first_hop", &"…")
            .field("origin_circuit_id", &self.origin_circuit_id)
            .field("circuit_keys", &"<redacted>")
            .finish()
    }
}

/// Build a circuit-setup envelope addressed through `hops` (`hops[0]` first,
/// `hops[N-1]` the terminus R), with freshly-random per-link ids + per-hop keys.
/// `terminus_payload` rides to R (e.g. a signed `CircuitRegisterPayload`).
/// Returns `(setup_envelope, origin_state)`: send the envelope to `hops[0]` as a
/// `CircuitBuild`; keep `origin_state` to open returns.
pub fn build_origin_circuit(
    hops: &[OriginHop],
    terminus_payload: &[u8],
    now_unix: u64,
) -> Result<(Vec<u8>, OriginCircuit), CircuitError> {
    if hops.is_empty() {
        return Err(CircuitError::NoHops);
    }
    let n = hops.len();
    // N link ids (id on link i = hop i's circuit_id_in) + N hop keys.
    let mut cids = vec![0u32; n];
    let mut keys = vec![[0u8; CIRCUIT_KEY_LEN]; n];
    for i in 0..n {
        let mut c = OsRng.next_u32();
        if c == 0 {
            c = 1; // keep ids nonzero (cosmetic; 0 is a valid id but avoid it)
        }
        cids[i] = c;
        OsRng.fill_bytes(&mut keys[i]);
    }
    let setup_hops: Vec<CircuitSetupHop> = (0..n)
        .map(|i| CircuitSetupHop {
            node_id: hops[i].node_id,
            pubkey: hops[i].pubkey,
            circuit_id_in: cids[i],
            circuit_id_out: if i + 1 < n { cids[i + 1] } else { 0 },
            circuit_key: keys[i],
        })
        .collect();
    let setup = build_circuit_setup(&setup_hops, terminus_payload)?;
    let origin = OriginCircuit {
        circuit_keys: keys,
        first_hop: hops[0].node_id,
        origin_circuit_id: cids[0],
        created_unix: now_unix,
        confirmed: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        is_reply: false, // callers building a REPLY circuit set this afterwards
    };
    Ok((setup, origin))
}

/// Bounded table of circuits THIS node originated, keyed by `(first_hop,
/// origin_circuit_id)` — the routing a return `CircuitData` carries when it
/// reaches the originator.
pub struct OriginCircuitTable {
    inner: Mutex<HashMap<(Link, CircuitId), Arc<OriginCircuit>>>,
    cap: usize,
    ttl_secs: u64,
}

impl OriginCircuitTable {
    /// Default cap on concurrently-originated circuits.
    pub const DEFAULT_CAP: usize = 256;
    /// Default idle TTL.
    pub const DEFAULT_TTL_SECS: u64 = 600;

    pub fn new() -> Self {
        Self::with_params(Self::DEFAULT_CAP, Self::DEFAULT_TTL_SECS)
    }

    pub fn with_params(cap: usize, ttl_secs: u64) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            cap: cap.max(1),
            ttl_secs,
        }
    }

    /// Record an originated circuit. Returns `false` if at capacity.
    pub fn insert(&self, circuit: Arc<OriginCircuit>) -> bool {
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let key = (circuit.first_hop, circuit.origin_circuit_id);
        if !g.contains_key(&key) && g.len() >= self.cap {
            return false;
        }
        g.insert(key, circuit);
        true
    }

    /// Resolve a return cell's `(first_hop, circuit_id)` to its origin state.
    pub fn lookup(&self, first_hop: &Link, circuit_id: CircuitId) -> Option<Arc<OriginCircuit>> {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&(*first_hop, circuit_id))
            .cloned()
    }

    pub fn remove(&self, first_hop: &Link, circuit_id: CircuitId) {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&(*first_hop, circuit_id));
    }

    pub fn gc(&self, now_unix: u64) -> usize {
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let ttl = self.ttl_secs;
        let before = g.len();
        g.retain(|_, c| now_unix.saturating_sub(c.created_unix) < ttl);
        before - g.len()
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for OriginCircuitTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit_data::{apply_layer, wrap_payload};
    use crate::circuit_setup::{SetupPeelResult, peel_circuit_setup};
    use x25519_dalek::{PublicKey, StaticSecret};

    fn hop() -> (StaticSecret, OriginHop) {
        let sk = StaticSecret::random_from_rng(OsRng);
        let pk = PublicKey::from(&sk).to_bytes();
        let h = OriginHop {
            node_id: {
                let mut id = [0u8; 32];
                OsRng.fill_bytes(&mut id);
                id
            },
            pubkey: pk,
        };
        (sk, h)
    }

    #[test]
    fn build_then_peel_through_relays_matches_origin_keys() {
        let (sk0, h0) = hop();
        let (sk1, h1) = hop();
        let (sk2, h2) = hop(); // terminus
        let (env, origin) = build_origin_circuit(&[h0, h1, h2], b"register", 1000).unwrap();
        assert_eq!(origin.circuit_keys.len(), 3);
        assert_eq!(origin.first_hop, h0.node_id);

        // Relay-side peels should recover exactly the keys the originator stored,
        // and route hop→hop, with the terminus seeing the payload.
        let r0 = peel_circuit_setup(&env, &sk0).unwrap();
        let inner0 = match r0 {
            SetupPeelResult::Forward {
                install,
                next_hop,
                inner,
            } => {
                assert_eq!(install.circuit_key, origin.circuit_keys[0]);
                assert_eq!(install.circuit_id_in, origin.origin_circuit_id);
                assert_eq!(next_hop, h1.node_id);
                inner
            }
            other => panic!("hop0 {other:?}"),
        };
        let inner1 = match peel_circuit_setup(&inner0, &sk1).unwrap() {
            SetupPeelResult::Forward {
                install,
                next_hop,
                inner,
            } => {
                assert_eq!(install.circuit_key, origin.circuit_keys[1]);
                assert_eq!(next_hop, h2.node_id);
                inner
            }
            other => panic!("hop1 {other:?}"),
        };
        match peel_circuit_setup(&inner1, &sk2).unwrap() {
            SetupPeelResult::Terminus { install, payload } => {
                assert_eq!(install.circuit_key, origin.circuit_keys[2]);
                assert_eq!(&*payload, b"register");
            }
            other => panic!("terminus {other:?}"),
        }
    }

    #[test]
    fn origin_opens_a_return_cell() {
        let (_s0, h0) = hop();
        let (_s1, h1) = hop();
        let (_s2, h2) = hop();
        let (_env, origin) = build_origin_circuit(&[h0, h1, h2], b"", 0).unwrap();
        let k = &origin.circuit_keys;
        let seq = 5u32;
        // Terminus wraps + applies its layer; intermediate hops apply theirs.
        let mut cell = wrap_payload(b"introduce-bytes").unwrap();
        apply_layer(&k[2], Direction::Return, seq, &mut cell);
        apply_layer(&k[1], Direction::Return, seq, &mut cell);
        apply_layer(&k[0], Direction::Return, seq, &mut cell);
        assert_eq!(origin.open_return(seq, &cell).unwrap(), b"introduce-bytes");
        // Wrong seq → wrong keystream → garbage. The framing check REJECTS most
        // garbage but is not authenticated, so with random per-run keys the
        // garbage occasionally parses (pre-existing ~1-in-few flake when this
        // asserted is_err()). The real invariant: the payload is never
        // recovered.
        assert!(
            origin
                .open_return(seq + 1, &cell)
                .map(|p| p != b"introduce-bytes")
                .unwrap_or(true),
            "wrong seq must never recover the true payload"
        );
    }

    #[test]
    fn origin_table_insert_lookup_cap_gc() {
        let t = OriginCircuitTable::with_params(1, 300);
        let (_s, h) = hop();
        let (_env, origin) = build_origin_circuit(&[h], b"", 100).unwrap();
        let oc = Arc::new(origin);
        assert!(t.insert(Arc::clone(&oc)));
        assert!(t.lookup(&oc.first_hop, oc.origin_circuit_id).is_some());

        // Cap = 1: a second distinct circuit is refused.
        let (_s2, h2) = hop();
        let (_e2, o2) = build_origin_circuit(&[h2], b"", 100).unwrap();
        assert!(!t.insert(Arc::new(o2)));

        // GC past TTL frees it.
        assert_eq!(t.gc(100 + 300), 1);
        assert!(t.is_empty());
    }
}
