//! Outbound anonymous-cell builder.
//!
//! Composition layer that closes the SEND-side anonymity pipeline.
//! Inputs:
//!
//! * Operator-supplied `payload` and `target` (the real recipient).
//! * A list [`super::directory::DiscoveredRelay`] candidates
//!   fetched + verified by the caller via
//!   [`super::directory::discover_relay_hops`].
//! * An RTT estimator (typically Vivaldi).
//! * Desired `hop_count` — total hops including the target.
//!
//! Output:
//!
//! * The `node_id` of the FIRST hop (where the cell needs to land
//!   on the wire — caller's session_tx_registry sends it as a
//!   fresh `RelayChain::Hop` frame).
//! * The 512-byte cell ready to send.
//!
//! Caller assembles the runtime-glue (DHT lookup for candidates
//! Vivaldi snapshot for RTT, session-registry for the actual
//! transmit). This keeps the composition itself pure and unit-
//! testable without standing up a real KademliaService /
//! VivaldiCoord / SessionTxRegistry.
//!
//! # `hop_count` semantics
//!
//! `hop_count` is the TOTAL number of nodes the cell traverses
//! INCLUDING the target. So:
//!
//! * `hop_count = 1` — direct send to target (no anonymity, just
//!   onion-encrypted point-to-point). Useful as a primitive
//!   baseline / when no relays are available.
//! * `hop_count = 2` — 1 relay + target. Hides target's identity
//!   from the relay (unlinkable), hides sender's identity from
//!   the target (sender appears as the relay).
//! * `hop_count = 3` — 2 relays + target. Tor-standard topology;
//!   sender's identity hidden from target AND from anyone past
//!   the first hop; target's identity hidden from anyone before
//!   the last hop.
//!
//! Higher hop counts trade payload budget for stronger
//! unlinkability — see [`super::packet::max_payload_for_hops`] for
//! the per-hop-count payload ceiling.
//!
//! # Why the target is passed directly (not discovered)
//!
//! The target's `x25519_pk` could in principle be discovered via
//! the same `discover_relay_hops` mechanism (target also publishes
//! its directory entry). We pass it directly here for two reasons:
//!
//! 1. Some targets DON'T want to be relays — `relay_capable =
//! false` means they won't publish a directory entry. The
//!    sender obtained the target's anonymity pubkey through
//!    another channel (sovereign-identity exchange, an out-of-
//!    band hand-off, etc.) and we don't want to require relay-
//!    capability just to RECEIVE anonymous messages.
//! 2. Splitting "lookup target" from "build cell" lets the
//!    caller resolve the target via different mechanisms per
//!    deployment (DHT, mailbox, hardcoded peer) without this
//!    helper having to know about all of them.

use super::cell::CELL_SIZE;
use super::circuit::Hop;
use super::circuit_builder::{
    pick_circuit_hops_latency_aware, pick_circuit_hops_latency_aware_with_diversity_and_reputation,
};
use super::directory::DiscoveredRelay;
use super::packet::{MAX_HOPS_PER_CELL, PacketError, build_anonymous_cell, max_payload_for_hops};

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum SenderError {
    #[error("hop_count must be >= 1 (got 0)")]
    ZeroHops,
    #[error("hop_count {hop_count} exceeds cell budget; max sendable is {max}")]
    HopCountExceedsCellBudget { hop_count: usize, max: usize },
    #[error("payload {got} B exceeds max for {hop_count}-hop circuit ({max} B)")]
    PayloadTooLarge {
        hop_count: usize,
        got: usize,
        max: usize,
    },
    #[error(
        "insufficient relay candidates: need {need} usable, have {have} \
         (after dedup + RTT-known filtering)"
    )]
    InsufficientRelayCandidates { need: usize, have: usize },
    #[error("packet: {0}")]
    Packet(PacketError),
    #[error("authenticated anonymous send requires a loaded sovereign identity")]
    MissingSenderIdentity,
    #[error(
        "reply requested but this node has no anonymity key — set [anonymity].receive_anonymous to be reply-capable"
    )]
    MissingReplyCapability,
}

impl From<PacketError> for SenderError {
    fn from(e: PacketError) -> Self {
        Self::Packet(e)
    }
}

/// `(first_hop_node_id, cell_bytes)` — caller sends `cell_bytes` to
/// `first_hop_node_id` via its session-tx-registry as a
/// `RelayChain::Hop` frame.
pub type OutboundAnonymousCell = ([u8; 32], [u8; CELL_SIZE]);

/// Whether the relay hops of a built circuit actually satisfied the
/// AS/netblock diversity gate, or silently degraded to latency-only
/// selection because no diverse set existed (all candidates shared a
/// `/16`, or the extractor returned `None` for everyone).
///
/// `build_outbound_anonymous_cell_with_diversity` discards this and is
/// kept for back-compat; callers that care about AS-correlation
/// resistance should use the `_reported` variant and surface
/// [`DiversityOutcome::DegradedToLatency`] (log/meter) so a silent loss
/// of diversity protection is observable. (audit cycle-8 F4.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiversityOutcome {
    /// The diversity-aware picker found `n_relays` distinct-key hops.
    Full,
    /// The diversity picker could not satisfy the constraint; the circuit
    /// fell back to latency-only selection (no AS-diversity guarantee).
    DegradedToLatency,
}

/// Build an outbound anonymous cell. Pure helper; caller is
/// responsible for fetching `discovered_candidates` from DHT and
/// supplying a usable `rtt_estimator` (typically Vivaldi-derived).
///
/// `hop_count` includes the target. When `hop_count == 1` the
/// candidate pool isn't consulted — the cell is built for the
/// target directly (1-hop). When `hop_count > 1`, `hop_count - 1`
/// relays are picked from the candidate pool by latency-aware
/// selection, then the target is appended as the final hop.
pub fn build_outbound_anonymous_cell<F>(
    payload: &[u8],
    discovered_candidates: &[DiscoveredRelay],
    rtt_estimator: F,
    target_node_id: [u8; 32],
    target_x25519_pk: [u8; 32],
    hop_count: usize,
) -> Result<OutboundAnonymousCell, SenderError>
where
    F: Fn(&[u8; 32]) -> Option<u32>,
{
    // Backwards-compat shim — production callers should switch to the
    // `_with_diversity` variant for AS-correlation resistance.  The
    // `|_| None` extractor lets every candidate pass the diversity
    // gate (effectively disabling it), preserving legacy behavior.
    build_outbound_anonymous_cell_with_diversity(
        payload,
        discovered_candidates,
        rtt_estimator,
        |_| None,
        target_node_id,
        target_x25519_pk,
        hop_count,
    )
}

/// Like [`build_outbound_anonymous_cell`] but additionally enforces
/// AS / netblock diversity between picked relay hops.  Anti-censorship
/// Epic 482.x — closes the "adversary controlling 3+ relays in one /16
/// (Hetzner, OVH, AWS-eu) can occupy ALL hops of a circuit" vector.
///
/// `diversity_key_of` maps a relay's `node_id` to an opaque key — typically
/// the first 16 bits of its IPv4 address (returned as `Some("v4:a.b")`)
/// or 32 bits of IPv6 (`Some("v6:xxxx:yyyy")`).  Returning `None` for
/// a candidate disables the diversity constraint for that relay (graceful
/// degradation — better to pick a no-key candidate than fail to build the
/// circuit entirely).
///
/// **Call-site responsibility:** the closure typically consults the
/// caller's `DiscoveredPeerCache` or session-tx-registry to look up
/// known IPs of relays we've already dialed.  Unknown relays receive
/// the "no constraint" treatment.  Future slice: extend the
/// `RelayDirectoryEntry` wire format with advertised_ip/asn so the
/// closure can derive keys for ALL candidates even without a prior dial.
///
/// Back-compat shim that discards the [`DiversityOutcome`]. New callers
/// that care about AS-correlation resistance should prefer
/// [`build_outbound_anonymous_cell_with_diversity_reported`] and surface a
/// [`DiversityOutcome::DegradedToLatency`] result.
pub fn build_outbound_anonymous_cell_with_diversity<F, K>(
    payload: &[u8],
    discovered_candidates: &[DiscoveredRelay],
    rtt_estimator: F,
    diversity_key_of: K,
    target_node_id: [u8; 32],
    target_x25519_pk: [u8; 32],
    hop_count: usize,
) -> Result<OutboundAnonymousCell, SenderError>
where
    F: Fn(&[u8; 32]) -> Option<u32>,
    K: Fn(&[u8; 32]) -> Option<String>,
{
    build_outbound_anonymous_cell_with_diversity_reported(
        payload,
        discovered_candidates,
        rtt_estimator,
        diversity_key_of,
        target_node_id,
        target_x25519_pk,
        hop_count,
    )
    .map(|(cell, _outcome)| cell)
}

/// Like [`build_outbound_anonymous_cell_with_diversity`] but also returns a
/// [`DiversityOutcome`] reporting whether the AS/netblock diversity gate was
/// actually satisfied or silently degraded to latency-only selection — so the
/// caller (which has logging/metrics) can make a loss of AS-correlation
/// protection observable instead of silent. (audit cycle-8 F4.)
///
/// Relay reputation is NOT consulted (the penalty is always 0); production
/// senders that want misbehaving-relay downweighting use
/// [`build_outbound_anonymous_cell_with_diversity_reported_and_reputation`].
pub fn build_outbound_anonymous_cell_with_diversity_reported<F, K>(
    payload: &[u8],
    discovered_candidates: &[DiscoveredRelay],
    rtt_estimator: F,
    diversity_key_of: K,
    target_node_id: [u8; 32],
    target_x25519_pk: [u8; 32],
    hop_count: usize,
) -> Result<(OutboundAnonymousCell, DiversityOutcome), SenderError>
where
    F: Fn(&[u8; 32]) -> Option<u32>,
    K: Fn(&[u8; 32]) -> Option<String>,
{
    build_outbound_anonymous_cell_with_diversity_reported_and_reputation(
        payload,
        discovered_candidates,
        rtt_estimator,
        diversity_key_of,
        |_| 0, // no reputation penalty
        target_node_id,
        target_x25519_pk,
        hop_count,
    )
}

/// Like [`build_outbound_anonymous_cell_with_diversity_reported`] but feeds a
/// per-relay reputation penalty (ms added to each candidate's effective RTT)
/// into hop selection, so relays with recorded failures sort behind viable
/// alternatives (Epic 482.3/482.4 Phase A wire-up — closes the gap noted in
/// `crate::relay_reputation`'s module doc). The penalty applies on the primary
/// AS-diverse selection path; the rare degraded latency-only fallback (no
/// AS-diverse set exists) stays reputation-unaware so a partial-protection
/// circuit still builds.
#[allow(clippy::too_many_arguments)]
pub fn build_outbound_anonymous_cell_with_diversity_reported_and_reputation<F, K, P>(
    payload: &[u8],
    discovered_candidates: &[DiscoveredRelay],
    rtt_estimator: F,
    diversity_key_of: K,
    reputation_penalty_ms: P,
    target_node_id: [u8; 32],
    target_x25519_pk: [u8; 32],
    hop_count: usize,
) -> Result<(OutboundAnonymousCell, DiversityOutcome), SenderError>
where
    F: Fn(&[u8; 32]) -> Option<u32>,
    K: Fn(&[u8; 32]) -> Option<String>,
    P: Fn(&[u8; 32]) -> u32,
{
    // A 1-hop circuit has no relay hops to diversify, so it is trivially "full".
    let mut diversity_outcome = DiversityOutcome::Full;
    if hop_count == 0 {
        return Err(SenderError::ZeroHops);
    }
    let max_payload = max_payload_for_hops(hop_count).ok_or(
        // pull the cap from the canonical
        // packet-budget constant rather than hardcoding `5` (which
        // becomes wrong if someone bumps cell size or onion overhead).
        SenderError::HopCountExceedsCellBudget {
            hop_count,
            max: MAX_HOPS_PER_CELL,
        },
    )?;
    if payload.len() > max_payload {
        return Err(SenderError::PayloadTooLarge {
            hop_count,
            got: payload.len(),
            max: max_payload,
        });
    }

    let n_relays = hop_count - 1;
    let mut hops: Vec<Hop> = Vec::with_capacity(hop_count);

    if n_relays > 0 {
        // Filter out the target from the candidate pool so it
        // doesn't get picked as a RELAY (which would put us into
        // the silly position of A→target→target). The picker
        // dedupes by node_id, but the target's node_id may not
        // appear in the candidate pool at all (target is non-
        // relay-capable) — so an explicit pre-filter is the
        // safer construction.
        let pool: Vec<DiscoveredRelay> = discovered_candidates
            .iter()
            .filter(|c| c.hop.node_id != target_node_id)
            .cloned()
            .collect();
        // AS-diversity selection (anti-censorship Epic 482.x wire-up):
        // delegates to `pick_circuit_hops_latency_aware_with_diversity`
        // with the caller-supplied `diversity_key_of` extractor.  When
        // the caller passes a `|_| None` extractor, behavior degrades
        // gracefully to legacy "no diversity" (every candidate gets
        // accepted regardless of AS prefix).  Production callers (sender
        // in veilcore) supply a closure that consults their local
        // `DiscoveredPeerCache` so already-dialed peers contribute
        // their /16 prefix to the diversity gate.
        //
        // Future tightening: extend `RelayDirectoryEntry` wire format
        // with advertised_ip/asn so unknown relays also get keys — currently
        // they pass through as "unkeyed candidates" by the picker's
        // graceful-degradation rule.
        //
        // Fallback to latency-only if the diversity picker can't find
        // `n_relays` distinct-key candidates (e.g., all candidates share
        // the same /16, or the extractor returns None for everyone).
        // This keeps a partial-AS-protection circuit working when a
        // strict-diversity circuit would fail outright.
        let (picked, outcome) = match pick_circuit_hops_latency_aware_with_diversity_and_reputation(
            &pool,
            n_relays,
            &rtt_estimator,
            &diversity_key_of,
            &reputation_penalty_ms,
        ) {
            Some(p) => (p, DiversityOutcome::Full),
            None => (
                // No diverse set exists — fall back to latency-only so a
                // partial-protection circuit still works rather than failing
                // outright, but report the degradation so the caller can meter it.
                pick_circuit_hops_latency_aware(&pool, n_relays, &rtt_estimator).ok_or(
                    SenderError::InsufficientRelayCandidates {
                        need: n_relays,
                        have: pool.len(),
                    },
                )?,
                DiversityOutcome::DegradedToLatency,
            ),
        };
        diversity_outcome = outcome;
        hops.extend(picked);
    }

    // Append target as the final hop.
    hops.push(Hop {
        node_id: target_node_id,
        pubkey: target_x25519_pk,
    });

    let cell = build_anonymous_cell(payload, &hops)?;
    let first_hop_node_id = hops[0].node_id;
    Ok(((first_hop_node_id, cell), diversity_outcome))
}

#[cfg(test)]
mod tests {
    use super::super::packet::{CellPeelResult, peel_anonymous_cell};
    use super::*;
    use rand_core::OsRng;
    use x25519_dalek::{PublicKey, StaticSecret};

    fn fresh_keypair() -> (StaticSecret, [u8; 32]) {
        let sk = StaticSecret::random_from_rng(OsRng);
        let pk = PublicKey::from(&sk).to_bytes();
        (sk, pk)
    }

    fn fresh_relay(id_byte: u8) -> (StaticSecret, DiscoveredRelay) {
        let (sk, pk) = fresh_keypair();
        let mut node_id = [0u8; 32];
        node_id[0] = id_byte;
        (
            sk,
            DiscoveredRelay {
                hop: Hop {
                    node_id,
                    pubkey: pk,
                },
                advertised_bps: 1_000_000,
                last_published_unix: 1_700_000_000,
            },
        )
    }

    #[test]
    fn epic482_7_zero_hops_rejected() {
        let (_, target_pk) = fresh_keypair();
        let err = build_outbound_anonymous_cell(b"x", &[], |_| None, [0u8; 32], target_pk, 0)
            .unwrap_err();
        assert_eq!(err, SenderError::ZeroHops);
    }

    #[test]
    fn epic482_7_one_hop_direct_to_target_no_relays_needed() {
        // hop_count = 1 means "no relays, send straight to target".
        // The cell is built with target as the only hop; the picker
        // is never invoked, so the candidate pool can be empty.
        let (target_sk, target_pk) = fresh_keypair();
        let mut target_id = [0u8; 32];
        target_id[0] = 0xAA;

        let (first_hop, cell) = build_outbound_anonymous_cell(
            b"direct send",
            &[], // no relay candidates needed
            |_| None,
            target_id,
            target_pk,
            1,
        )
        .expect("1-hop must succeed with no relays");

        assert_eq!(first_hop, target_id, "1-hop: first hop IS the target");

        // Target peels and gets the payload directly.
        match peel_anonymous_cell(&cell, &target_sk).unwrap() {
            CellPeelResult::Final { payload } => assert_eq!(payload.as_slice(), b"direct send"),
            other => panic!("expected Final, got {other:?}"),
        }
    }

    #[test]
    fn epic482_3_reputation_penalty_downweights_misbehaving_relay() {
        // Two relays with IDENTICAL RTT. A reputation penalty on one must push
        // it behind the other so the clean relay is chosen as the (single)
        // circuit hop — the wire-up that activates RelayReputation in selection.
        let (_sk_a, relay_a) = fresh_relay(0xAA);
        let (_sk_b, relay_b) = fresh_relay(0xBB);
        let (_t_sk, target_pk) = fresh_keypair();
        let target_id = [0xCC; 32];
        let a_id = relay_a.hop.node_id;
        let b_id = relay_b.hop.node_id;
        let pool = vec![relay_a, relay_b];

        let equal_rtt = |_: &[u8; 32]| Some(50u32);
        let no_diversity = |_: &[u8; 32]| None;

        // Baseline: no penalty → stable sort keeps pool order → A (first) wins.
        let ((first_hop_baseline, _), _) =
            build_outbound_anonymous_cell_with_diversity_reported_and_reputation(
                b"p",
                &pool,
                equal_rtt,
                no_diversity,
                |_| 0,
                target_id,
                target_pk,
                2,
            )
            .expect("baseline circuit builds");
        assert_eq!(
            first_hop_baseline, a_id,
            "baseline: A is picked (equal RTT, pool order)"
        );

        // Penalize A heavily → B must now be chosen instead.
        let penalize_a = move |nid: &[u8; 32]| if *nid == a_id { 100_000 } else { 0 };
        let ((first_hop_penalized, _), _) =
            build_outbound_anonymous_cell_with_diversity_reported_and_reputation(
                b"p",
                &pool,
                equal_rtt,
                no_diversity,
                penalize_a,
                target_id,
                target_pk,
                2,
            )
            .expect("penalized circuit still builds");
        assert_eq!(
            first_hop_penalized, b_id,
            "a relay with a reputation penalty must be avoided in favour of a clean one",
        );
    }

    #[test]
    fn epic482_7_three_hop_circuit_targets_via_two_relays() {
        // 3-hop: relay1 → relay2 → target. Standard Tor-style topology.
        let (sk_relay1, relay1) = fresh_relay(0x01);
        let (sk_relay2, relay2) = fresh_relay(0x02);
        let (target_sk, target_pk) = fresh_keypair();
        let mut target_id = [0u8; 32];
        target_id[0] = 0xCC;

        // RTT estimator: relay1 is faster than relay2.
        let rtts: std::collections::HashMap<u8, u32> =
            [(0x01, 10), (0x02, 50)].iter().copied().collect();
        let estimator = |id: &[u8; 32]| rtts.get(&id[0]).copied();

        let (first_hop, cell) = build_outbound_anonymous_cell(
            b"3-hop payload",
            &[relay1, relay2],
            estimator,
            target_id,
            target_pk,
            3,
        )
        .expect("3-hop with 2 relays must succeed");

        // First hop is the lower-RTT relay.
        assert_eq!(
            first_hop[0], 0x01,
            "first hop should be the lower-RTT relay (latency-aware)"
        );

        // Walk the circuit: relay1 → forward → relay2 → forward → target.
        let to_relay2 = match peel_anonymous_cell(&cell, &sk_relay1).unwrap() {
            CellPeelResult::Forward {
                next_hop,
                outbound_cell,
            } => {
                assert_eq!(next_hop[0], 0x02, "relay1 forwards to relay2");
                outbound_cell
            }
            other => panic!("relay1 must Forward, got {other:?}"),
        };
        let to_target = match peel_anonymous_cell(&to_relay2, &sk_relay2).unwrap() {
            CellPeelResult::Forward {
                next_hop,
                outbound_cell,
            } => {
                assert_eq!(next_hop, target_id, "relay2 forwards to target");
                outbound_cell
            }
            other => panic!("relay2 must Forward, got {other:?}"),
        };
        match peel_anonymous_cell(&to_target, &target_sk).unwrap() {
            CellPeelResult::Final { payload } => assert_eq!(payload.as_slice(), b"3-hop payload"),
            other => panic!("target must yield Final, got {other:?}"),
        }
    }

    #[test]
    fn epic482_7_insufficient_relay_candidates_rejected() {
        // Asking for 3 hops but candidate pool has only 1 relay.
        let (_, relay1) = fresh_relay(0x01);
        let (_, target_pk) = fresh_keypair();
        let mut target_id = [0u8; 32];
        target_id[0] = 0xCC;

        let err = build_outbound_anonymous_cell(
            b"x",
            &[relay1],
            |_| Some(10),
            target_id,
            target_pk,
            3, // need 2 relays, have 1
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                SenderError::InsufficientRelayCandidates { need: 2, have: 1 }
            ),
            "expected InsufficientRelayCandidates, got {err:?}"
        );
    }

    #[test]
    fn epic482_7_target_excluded_from_relay_pool() {
        // The target appears in the candidate pool (suppose target
        // is also relay-capable and published its own directory
        // entry). The picker MUST NOT pick it as a relay — would
        // produce A → target → target which leaks target identity
        // to relay pool members.
        let (target_sk, target_pk) = fresh_keypair();
        let mut target_id = [0u8; 32];
        target_id[0] = 0xCC;
        // Build a "candidate" entry for the target (as if target also
        // published a relay-directory entry).
        let target_as_candidate = DiscoveredRelay {
            hop: Hop {
                node_id: target_id,
                pubkey: target_pk,
            },
            advertised_bps: 1_000_000,
            last_published_unix: 1_700_000_000,
        };
        let (_, relay1) = fresh_relay(0x01);
        let (_, relay2) = fresh_relay(0x02);

        // 3-hop request: 2 relays + target. Pool has [target, relay1
        // relay2]. Target must be filtered out before the picker
        // runs — leaving exactly 2 relays = exactly enough.
        let (first_hop, _cell) = build_outbound_anonymous_cell(
            b"x",
            &[target_as_candidate, relay1, relay2],
            |_| Some(10),
            target_id,
            target_pk,
            3,
        )
        .expect("3-hop must succeed when target filtered from relay pool");

        // First hop is one of relay1 / relay2 — NOT the target.
        assert_ne!(
            first_hop, target_id,
            "first hop must not be the target (would short-circuit anonymity)"
        );
        let _ = target_sk;
    }

    #[test]
    fn epic482_7_payload_too_large_rejected_pre_build() {
        let (_, target_pk) = fresh_keypair();
        let target_id = [0u8; 32];
        // Max payload for 1-hop is 418 B (per packet::max_payload_for_hops).
        // Push past it.
        let oversized = vec![0u8; 500];
        let err = build_outbound_anonymous_cell(&oversized, &[], |_| None, target_id, target_pk, 1)
            .unwrap_err();
        assert!(
            matches!(err, SenderError::PayloadTooLarge { .. }),
            "expected PayloadTooLarge, got {err:?}"
        );
    }

    #[test]
    fn epic482_7_too_many_hops_rejected_pre_picker() {
        // packet::max_payload_for_hops returns None for hop_count >= 6.
        let (_, target_pk) = fresh_keypair();
        let err = build_outbound_anonymous_cell(b"x", &[], |_| None, [0u8; 32], target_pk, 7)
            .unwrap_err();
        assert!(
            matches!(err, SenderError::HopCountExceedsCellBudget { .. }),
            "expected HopCountExceedsCellBudget, got {err:?}"
        );
    }

    #[test]
    fn epic482_7_two_hop_uses_one_relay_then_target() {
        // 2-hop is the smallest "real anonymity" topology — target
        // can't see sender's IP; relay sees both but doesn't see
        // payload (target's anonymity-key encrypts it).
        let (sk_relay, relay) = fresh_relay(0x99);
        let (target_sk, target_pk) = fresh_keypair();
        let mut target_id = [0u8; 32];
        target_id[0] = 0xCC;

        let (first_hop, cell) = build_outbound_anonymous_cell(
            b"2-hop test",
            &[relay],
            |_| Some(10),
            target_id,
            target_pk,
            2,
        )
        .expect("2-hop with 1 relay must succeed");

        assert_eq!(first_hop[0], 0x99, "first hop is the relay");

        let to_target = match peel_anonymous_cell(&cell, &sk_relay).unwrap() {
            CellPeelResult::Forward {
                next_hop,
                outbound_cell,
            } => {
                assert_eq!(next_hop, target_id);
                outbound_cell
            }
            other => panic!("relay must Forward, got {other:?}"),
        };
        match peel_anonymous_cell(&to_target, &target_sk).unwrap() {
            CellPeelResult::Final { payload } => assert_eq!(payload.as_slice(), b"2-hop test"),
            other => panic!("target must yield Final, got {other:?}"),
        }
    }

    /// The full pipeline from end-to-end: discovery → picker → packet
    /// → relay handler peel → target receives. This is the contract
    /// every anonymity-using app will exercise; if any of the layers
    /// drift this test trips before reaching the dispatcher.
    #[test]
    fn epic482_7_end_to_end_send_through_three_hops_recovers_payload() {
        let (sk1, relay1) = fresh_relay(0x10);
        let (sk2, relay2) = fresh_relay(0x20);
        let (sk3, relay3) = fresh_relay(0x30);
        let (target_sk, target_pk) = fresh_keypair();
        let mut target_id = [0u8; 32];
        target_id[0] = 0xFF;

        // RTT estimator favors relay1, then relay2, then relay3.
        let rtts: std::collections::HashMap<u8, u32> = [(0x10, 10), (0x20, 20), (0x30, 30)]
            .iter()
            .copied()
            .collect();

        let payload = b"end-to-end anonymous via 3-hop";
        let (first_hop, cell) = build_outbound_anonymous_cell(
            payload,
            &[relay3, relay2, relay1], // intentional reverse-order to
            // verify picker sorts by RTT
            |id| rtts.get(&id[0]).copied(),
            target_id,
            target_pk,
            3,
        )
        .expect("3-hop e2e build");

        // Walk: relay1 (fastest) → relay2 → target.
        assert_eq!(first_hop[0], 0x10);
        let c2 = match peel_anonymous_cell(&cell, &sk1).unwrap() {
            CellPeelResult::Forward {
                next_hop,
                outbound_cell,
            } => {
                assert_eq!(
                    next_hop[0], 0x20,
                    "after relay1, next is relay2 (next-fastest)"
                );
                outbound_cell
            }
            _ => unreachable!(),
        };
        let c3 = match peel_anonymous_cell(&c2, &sk2).unwrap() {
            CellPeelResult::Forward {
                next_hop,
                outbound_cell,
            } => {
                assert_eq!(next_hop, target_id);
                outbound_cell
            }
            _ => unreachable!(),
        };
        match peel_anonymous_cell(&c3, &target_sk).unwrap() {
            CellPeelResult::Final { payload: p } => assert_eq!(p.as_slice(), payload),
            _ => unreachable!(),
        }
        // relay3 was never used (we picked top 2 by RTT for a 3-hop
        // circuit and 3rd-fastest = relay3 didn't make the cut).
        let _ = sk3;
    }

    // ── AS-diversity wire-up tests (Epic 482.x follow-up) ────────

    /// `_with_diversity` with a constant-None extractor degrades to the
    /// legacy "no diversity" behaviour — picker accepts everyone.
    #[test]
    fn epic482_diversity_extractor_none_degrades_to_legacy() {
        let (_, relay1) = fresh_relay(0x01);
        let (_, relay2) = fresh_relay(0x02);
        let (_, target_pk) = fresh_keypair();
        let mut target_id = [0u8; 32];
        target_id[0] = 0xCC;

        let (first_hop, _cell) = build_outbound_anonymous_cell_with_diversity(
            b"payload",
            &[relay1, relay2],
            |_| Some(10),
            |_| None, // no diversity keys for anyone — picker accepts all
            target_id,
            target_pk,
            3,
        )
        .expect("None-extractor must degrade gracefully");
        // First hop is a relay (not the target).
        assert_ne!(first_hop, target_id);
    }

    /// When two relays share the same AS prefix, picker must
    /// reject one of them — but fall back to the legacy non-diversity
    /// picker rather than fail outright.  Test asserts the fallback
    /// fires (circuit builds successfully) and at least one hop carries
    /// a distinct key.
    #[test]
    fn epic482_diversity_fallback_to_latency_when_strict_diversity_unsatisfiable() {
        // Two relays on the same /16 + one more not in pool.  Strict
        // diversity needs 2 distinct /16s for 2 relay hops — impossible
        // with only 2 relays sharing one /16.  Expectation: fallback to
        // pick_circuit_hops_latency_aware fires, circuit still builds.
        let (_, relay1) = fresh_relay(0x01);
        let (_, relay2) = fresh_relay(0x02);
        let (_, target_pk) = fresh_keypair();
        let mut target_id = [0u8; 32];
        target_id[0] = 0xCC;

        let result = build_outbound_anonymous_cell_with_diversity(
            b"payload",
            &[relay1, relay2],
            |_| Some(10),
            // Both relays share AS "v4:10.0" — strict diversity unsatisfiable.
            |_| Some("v4:10.0".to_owned()),
            target_id,
            target_pk,
            3,
        );
        assert!(
            result.is_ok(),
            "fallback to latency-aware must succeed: {:?}",
            result.err()
        );
    }

    /// audit cycle-8 F4 — the `_reported` variant must surface the silent
    /// loss of AS-diversity protection so the caller can meter it: a
    /// two-relays-one-/16 pool degrades to latency-only, two distinct /16s
    /// stays Full.
    #[test]
    fn diversity_reported_flags_degradation() {
        let (_, relay1) = fresh_relay(0x01);
        let (_, relay2) = fresh_relay(0x02);
        let (_, target_pk) = fresh_keypair();
        let mut target_id = [0u8; 32];
        target_id[0] = 0xCC;

        // Both relays share one /16 → strict diversity unsatisfiable → degraded.
        let (_, outcome) = build_outbound_anonymous_cell_with_diversity_reported(
            b"payload",
            &[relay1.clone(), relay2.clone()],
            |_| Some(10),
            |_| Some("v4:10.0".to_owned()),
            target_id,
            target_pk,
            3,
        )
        .expect("fallback builds");
        assert_eq!(outcome, DiversityOutcome::DegradedToLatency);

        // Distinct /16s → strict diversity satisfied → Full.
        let (_, outcome) = build_outbound_anonymous_cell_with_diversity_reported(
            b"payload",
            &[relay1, relay2],
            |_| Some(10),
            |id: &[u8; 32]| Some(format!("v4:10.{}", id[0])),
            target_id,
            target_pk,
            3,
        )
        .expect("diverse builds");
        assert_eq!(outcome, DiversityOutcome::Full);
    }

    /// When two relays have distinct AS keys, picker should select
    /// both (strict-diversity path succeeds).  Latency-aware fallback
    /// NOT consulted.
    #[test]
    fn epic482_diversity_picks_distinct_as_when_available() {
        let (sk_relay1, relay1) = fresh_relay(0x01);
        let (sk_relay2, relay2) = fresh_relay(0x02);
        let (target_sk, target_pk) = fresh_keypair();
        let mut target_id = [0u8; 32];
        target_id[0] = 0xCC;

        // Relay1 in /16 "10.0", relay2 in /16 "20.0".  Distinct AS,
        // strict-diversity path succeeds.
        let as_keys: std::collections::HashMap<u8, &'static str> =
            [(0x01, "v4:10.0"), (0x02, "v4:20.0")]
                .iter()
                .copied()
                .collect();
        let diversity =
            move |id: &[u8; 32]| -> Option<String> { as_keys.get(&id[0]).map(|s| s.to_string()) };

        let (first_hop, cell) = build_outbound_anonymous_cell_with_diversity(
            b"diverse payload",
            &[relay1, relay2],
            |id: &[u8; 32]| if id[0] == 0x01 { Some(10) } else { Some(50) },
            diversity,
            target_id,
            target_pk,
            3,
        )
        .expect("distinct AS must build");

        // Lower-RTT relay (0x01) wins first hop.
        assert_eq!(first_hop[0], 0x01);

        // Sanity-check the full circuit peels through both relays + target.
        let to_relay2 = match peel_anonymous_cell(&cell, &sk_relay1).unwrap() {
            CellPeelResult::Forward {
                next_hop,
                outbound_cell,
            } => {
                assert_eq!(next_hop[0], 0x02);
                outbound_cell
            }
            _ => unreachable!(),
        };
        let to_target = match peel_anonymous_cell(&to_relay2, &sk_relay2).unwrap() {
            CellPeelResult::Forward { outbound_cell, .. } => outbound_cell,
            _ => unreachable!(),
        };
        match peel_anonymous_cell(&to_target, &target_sk).unwrap() {
            CellPeelResult::Final { payload } => assert_eq!(payload.as_slice(), b"diverse payload"),
            _ => unreachable!(),
        }
    }
}
