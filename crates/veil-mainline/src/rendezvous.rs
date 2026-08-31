//! Where veil nodes agree to meet on a DHT that knows nothing about veil.
//!
//! The Mainline DHT indexes 20-byte infohashes and does not care what they
//! mean. So veil picks one, every node announces itself on it, and a node
//! looking for its first peer asks who else is there. Nothing on the DHT side
//! has to cooperate, know, or consent.
//!
//! # This is public, and that is not a mistake to be fixed
//!
//! Anybody who has this source can compute the same infohash and ask the same
//! question, and will get back the address of every veil node that announced.
//! That is not a flaw in the derivation — a rendezvous every veil node can
//! find is a rendezvous everyone can find, and no amount of hashing changes
//! it. It is the reason announcing is opt-in (`global.bootstrap`) and the
//! reason the honest description of this layer is "public entry point", not
//! "private discovery".
//!
//! What it is not is a list somebody hosts. The project publishes no seed
//! addresses, operates nothing, and cannot be served notice to take down what
//! it does not run.
//!
//! # Why it moves
//!
//! The infohash changes every [`EPOCH`]. A crawler's list of veil nodes goes
//! stale on its own, a node that stops announcing disappears without having to
//! be forgotten by anyone, and the DHT's own storage — which expires
//! announcements anyway — is not asked to hold anything for longer than it
//! keeps things.
//!
//! Both the current epoch and the previous one are used, always. A node whose
//! clock is an hour off, or that happens to look up as the epoch turns, would
//! otherwise search a rendezvous nobody else is at — and nothing in either
//! node's log would say why. Two epochs cost one more lookup and remove the
//! whole class.

use crate::krpc::NodeId;

/// How long one rendezvous point lasts.
pub const EPOCH: std::time::Duration = std::time::Duration::from_secs(24 * 60 * 60);

const DOMAIN: &[u8] = b"veil.bootstrap.mainline-rendezvous.v1";

/// Which network's rendezvous. Production and the testnet must never meet:
/// they are separate networks, and a node that dials across the boundary
/// wastes a handshake at best and mixes two node sets at worst.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    Production,
    Testnet,
}

impl Network {
    const fn label(self) -> &'static [u8] {
        match self {
            Self::Production => b"production",
            Self::Testnet => b"testnet",
        }
    }

    /// Every network, so a guard can walk them rather than trust a list.
    pub const ALL: &'static [Network] = &[Network::Production, Network::Testnet];
}

/// The epoch number containing `unix_seconds`.
pub fn epoch_of(unix_seconds: u64) -> u64 {
    unix_seconds / EPOCH.as_secs()
}

/// The rendezvous infohash for one network and epoch.
pub fn infohash(network: Network, epoch: u64) -> NodeId {
    let mut h = blake3::Hasher::new();
    h.update(DOMAIN);
    h.update(network.label());
    h.update(&epoch.to_be_bytes());
    let full = h.finalize();
    let mut id = [0u8; 20];
    id.copy_from_slice(&full.as_bytes()[..20]);
    NodeId(id)
}

/// The rendezvous points to use right now: this epoch and the one before.
///
/// Ordered current-first, because that is where most nodes are, and a caller
/// that can only afford one lookup should spend it there.
pub fn current_infohashes(network: Network, unix_seconds: u64) -> [NodeId; 2] {
    let epoch = epoch_of(unix_seconds);
    [
        infohash(network, epoch),
        infohash(network, epoch.saturating_sub(1)),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    const DAY: u64 = 24 * 60 * 60;

    #[test]
    fn the_two_networks_never_meet() {
        // They are separate networks. A shared rendezvous would have testnet
        // nodes dialling production ones, which is a class of confusion this
        // project has paid for before.
        let mut seen = HashSet::new();
        for network in Network::ALL {
            for epoch in 0..8 {
                assert!(
                    seen.insert(infohash(*network, epoch)),
                    "{network:?} epoch {epoch} collides with another rendezvous"
                );
            }
        }
        assert_eq!(
            seen.len(),
            Network::ALL.len() * 8,
            "a network or an epoch produced no distinct point"
        );
    }

    #[test]
    fn the_point_moves_once_a_day_and_not_within_one() {
        let start = 1_700_000_000u64 / DAY * DAY; // a day boundary
        let inside = [start, start + 1, start + DAY / 2, start + DAY - 1];
        let first = infohash(Network::Production, epoch_of(inside[0]));
        for t in inside {
            assert_eq!(
                infohash(Network::Production, epoch_of(t)),
                first,
                "the rendezvous moved inside a single epoch, at {t}"
            );
        }
        assert_ne!(
            infohash(Network::Production, epoch_of(start + DAY)),
            first,
            "the rendezvous did not move at the epoch boundary"
        );
    }

    #[test]
    fn a_clock_that_is_wrong_by_hours_still_meets_everyone() {
        // The failure this removes is silent: two nodes searching different
        // rendezvous points, both working perfectly, neither finding the
        // other, and nothing in either log saying why.
        let boundary = 1_700_000_000u64 / DAY * DAY + DAY;
        // One node just after the turn, one still an hour before it.
        let after = current_infohashes(Network::Production, boundary + 60);
        let before = current_infohashes(Network::Production, boundary - 3600);
        let shared: Vec<&NodeId> = after.iter().filter(|h| before.contains(h)).collect();
        assert!(
            !shared.is_empty(),
            "a node an hour behind shares no rendezvous with one just past the turn"
        );
    }

    #[test]
    fn the_current_epoch_comes_first() {
        // A caller that can afford one lookup should spend it where most
        // nodes are.
        let now = 1_700_000_000u64;
        let points = current_infohashes(Network::Production, now);
        assert_eq!(points[0], infohash(Network::Production, epoch_of(now)));
        assert_eq!(points[1], infohash(Network::Production, epoch_of(now) - 1));
        assert_ne!(points[0], points[1]);
    }

    #[test]
    fn epoch_zero_does_not_underflow_into_the_far_future() {
        // A machine whose clock says 1970 must not compute epoch -1 and land
        // on a rendezvous nobody will ever use again.
        let points = current_infohashes(Network::Production, 0);
        assert_eq!(
            points[0], points[1],
            "epoch 0 has no predecessor to differ from"
        );
    }

    #[test]
    fn an_infohash_is_twenty_bytes_and_not_obviously_structured() {
        let h = infohash(Network::Production, 42);
        assert_eq!(h.0.len(), 20);
        assert_ne!(h.0, [0u8; 20]);
        // Consecutive epochs must not produce neighbouring points: adjacent
        // infohashes would put every veil rendezvous in one region of the
        // keyspace, which is a thing a crawler can watch cheaply.
        let a = infohash(Network::Production, 42);
        let b = infohash(Network::Production, 43);
        let differing = a.0.iter().zip(b.0.iter()).filter(|(x, y)| x != y).count();
        assert!(
            differing > 10,
            "consecutive epochs differ in only {differing} of 20 bytes"
        );
    }
}
