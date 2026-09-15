//! WHICH of the strangers at a meeting point this node calls, and in what order.
//!
//! There was no answer to that question. Both rendezvous loops walked the
//! index's own list from the top and dialled the first few that survived the
//! filters, so the order was whatever the index felt like: a Nostr relay
//! honours `limit` by returning the NEWEST records (NIP-01), and the DHT walk
//! towards a rotating infohash is deterministic, so two clients that look in
//! the same minute get near-identical lists and ring the same doors. At four
//! announcing hosts that is invisible. At a thousand it means the newest few
//! carry everyone, and whoever republishes most often is the one everyone
//! meets — a position bought with a cron job rather than earned.
//!
//! THE ORDER IS A RANDOM POINT AND A PLACE DERIVED FROM IT. Each pass draws a
//! fresh 32-byte probe from the OS, and a candidate's place in the queue is
//! `BLAKE3(probe | transport)`, smallest first. The nearest is tried first; if
//! it does not answer the walk continues outward, which is the widening — the
//! existing budget (`MAX_RENDEZVOUS_ATTEMPTS` tried, `MAX_RENDEZVOUS_PEERS`
//! kept) decides where it stops. No extra machinery: "take the nearest few,
//! widen on failure, stop when you have enough" is exactly what walking this
//! order under those caps already does.
//!
//! KEYED, NOT XOR — AND THAT WAS MEASURED, NOT REASONED. The first version of
//! this file did the obvious Kademlia thing: XOR distance between the probe
//! and `BLAKE3(transport)`, nearest first. It is biased, and not slightly.
//! Under XOR the candidates sit in a binary trie and a uniformly random probe
//! falls into one of their Voronoi cells — cells whose sizes differ by however
//! the digests happen to cluster. An address whose digest is isolated owns a
//! large cell and leads far more often than its share; one sharing a long
//! prefix with a neighbour splits a small cell and leads far less. The
//! fairness test below caught it on its first run: ten candidates, ten
//! thousand fresh probes, one of them leading 650 times against an expected
//! 1000, and 1215 on the next run.
//!
//! That bias is fixed per address, so it would persist across every pass
//! forever — the same uneven load this module exists to remove, arriving by a
//! different road. Hashing the probe TOGETHER WITH the address gives each
//! candidate an independent uniform key per pass instead, so the order is a
//! uniformly random permutation and no address has a share to own.
//!
//! WHY THE PROBE IS RANDOM AND NOT THIS NODE'S ID. Kademlia distance invites
//! it — the node id is right there, it needs no entropy, and it would give a
//! stable, self-balancing assignment. It would also be a deanonymiser. The set
//! of peers a node rings would become a function of its identity: anyone who
//! can watch dials at a public meeting point — a relay operator sees every
//! subscriber, a DHT node sees every `get_peers` — could take the observed
//! choices, sort candidates by distance from each guessed id, and keep the id
//! that predicts them. It would survive a new IP, a restart, and a fresh Nostr
//! key, because those change nothing about the distances. A per-pass random
//! probe predicts nothing about the next pass and nothing about who is asking.
//!
//! So the probe is drawn fresh, never stored, never published, and never
//! derived from anything this node is. The identity this file must not take as
//! an argument is the whole point of the file.

/// A point in node-id space, drawn for one rendezvous pass and thrown away.
///
/// Not `Clone` and not `Copy` on purpose: a probe that gets carried from one
/// pass to the next is a stable ordering again, which is the property this
/// exists to remove.
pub(crate) struct MeetingProbe([u8; 32]);

impl MeetingProbe {
    /// A fresh point from the OS.
    pub(crate) fn fresh() -> Self {
        use rand_core::RngCore;
        let mut bytes = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// For tests that need to pin an order. Never reachable from the loops.
    #[cfg(test)]
    pub(crate) fn at(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// Candidate addresses, nearest to `probe` first.
///
/// A candidate's place is `BLAKE3(probe ‖ transport)`, over the address as it
/// would be dialled. Because the probe is fresh and unpublished, those keys
/// are independent and uniform, so the result is a uniformly random
/// permutation with no address holding a share of the front. See the module
/// header for the XOR version this replaced and the measurement that rejected
/// it.
///
/// The address is keyed as it would be DIALLED, so the same host at the same
/// port keys the same whichever index named it, and a host cannot buy a better
/// place without moving to a different address.
///
/// Takes the probe and the candidates and NOTHING ELSE. In particular it does
/// not take the local node id: see the module header for what that would cost.
pub(crate) fn nearest_first(probe: &MeetingProbe, candidates: Vec<String>) -> Vec<String> {
    let mut keyed: Vec<([u8; 32], String)> = candidates
        .into_iter()
        .map(|transport| (queue_key(&probe.0, transport.as_bytes()), transport))
        .collect();
    // By key, then by the address itself. The tiebreak is unreachable for
    // distinct addresses — two BLAKE3 digests do not collide — and exists so
    // the function is a total order rather than one that leaves equal elements
    // wherever the sort found them.
    keyed.sort_unstable_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    keyed.into_iter().map(|(_, transport)| transport).collect()
}

fn queue_key(probe: &[u8; 32], transport: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(probe);
    hasher.update(transport);
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidates(n: usize) -> Vec<String> {
        (0..n)
            .map(|i| format!("obfs4-tcp://10.0.0.{i}:4433"))
            .collect()
    }

    #[test]
    fn every_candidate_survives_the_ordering() {
        // A reorder that loses or duplicates an address is a peer table that
        // silently cannot see part of the network.
        let all = candidates(50);
        let ordered = nearest_first(&MeetingProbe::fresh(), all.clone());
        assert_eq!(ordered.len(), all.len());
        let mut sorted_in = all;
        let mut sorted_out = ordered;
        sorted_in.sort();
        sorted_out.sort();
        assert_eq!(sorted_in, sorted_out);
    }

    #[test]
    fn the_same_probe_gives_the_same_order() {
        // Within one pass the order has to be an order, not a coin flipped per
        // comparison.
        let all = candidates(30);
        let probe = [7u8; 32];
        assert_eq!(
            nearest_first(&MeetingProbe::at(probe), all.clone()),
            nearest_first(&MeetingProbe::at(probe), all)
        );
    }

    #[test]
    fn a_different_probe_gives_a_different_order() {
        // The control for the test above: an order that never changes is the
        // defect this module exists for, and it would pass the determinism
        // test perfectly.
        let all = candidates(30);
        assert_ne!(
            nearest_first(&MeetingProbe::at([1u8; 32]), all.clone()),
            nearest_first(&MeetingProbe::at([2u8; 32]), all)
        );
    }

    #[test]
    fn no_candidate_owns_the_front_of_the_queue() {
        // THE PROPERTY THAT MATTERS AT A THOUSAND HOSTS. Being first is what
        // gets a host dialled, so if any address were even modestly favoured
        // the whole change would be decoration.
        //
        // Ten candidates, ten thousand fresh probes: each should lead about a
        // thousand times. The bound is wide enough that a correct
        // implementation will not trip it in the life of this project and
        // narrow enough to catch a real bias -- the old behaviour, first in
        // the list always first, scores 10000/0.
        let all = candidates(10);
        let mut first = std::collections::HashMap::new();
        for _ in 0..10_000 {
            let ordered = nearest_first(&MeetingProbe::fresh(), all.clone());
            *first.entry(ordered[0].clone()).or_insert(0usize) += 1;
        }
        assert_eq!(first.len(), all.len(), "some candidate never led");
        for (address, count) in &first {
            assert!(
                (800..=1200).contains(count),
                "{address} led {count} times of 10000; the order is not fair"
            );
        }
    }

    #[test]
    fn position_does_not_follow_a_node_id() {
        // The deanonymiser, written down as a test so the cheap version cannot
        // come back unnoticed.
        //
        // If the order were computed from the local node id, then a watcher
        // holding a guess at that id could sort candidates by distance from it
        // and predict the dials. Here the probe is drawn per pass, so the
        // best any fixed reference point can do is chance: across many passes
        // the candidate nearest to ANY fixed id leads no more often than the
        // rest.
        let all = candidates(10);
        let guessed_id = [0x5au8; 32];
        let nearest_to_id = nearest_first(&MeetingProbe::at(guessed_id), all.clone())[0].clone();
        let mut led = 0usize;
        for _ in 0..5_000 {
            if nearest_first(&MeetingProbe::fresh(), all.clone())[0] == nearest_to_id {
                led += 1;
            }
        }
        assert!(
            (350..=650).contains(&led),
            "the candidate nearest a fixed id led {led} times of 5000 — the \
             order is predictable from a guessed identity"
        );
    }
}
