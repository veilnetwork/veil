//! Where on a relay veil nodes agree to look, and who they look as.
//!
//! Two derivations, both from public inputs, both for the same reason as the
//! DHT's infohash: a rendezvous every veil node can find is one everybody can
//! find, and no amount of hashing changes that. What it buys is that the
//! project publishes no address and operates nothing.

use k256::schnorr::SigningKey;

/// How long one rendezvous label lasts. A day, as on the DHT.
pub const EPOCH: std::time::Duration = std::time::Duration::from_secs(24 * 60 * 60);

const DOMAIN: &[u8] = b"veil.bootstrap.nostr-rendezvous.v1";

/// Which network's rendezvous. Production and the testnet must never meet.
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

    /// Every network, so a guard can walk them.
    pub const ALL: &'static [Network] = &[Network::Production, Network::Testnet];
}

/// The epoch containing `unix_seconds`.
pub fn epoch_of(unix_seconds: u64) -> u64 {
    unix_seconds / EPOCH.as_secs()
}

/// The `d` tag veil nodes publish under and filter on.
///
/// Hex rather than raw bytes: it travels in JSON, and a tag value that is not
/// valid UTF-8 is a tag some relay will refuse to store.
pub fn label(network: Network, epoch: u64) -> String {
    let mut h = blake3::Hasher::new();
    h.update(DOMAIN);
    h.update(network.label());
    h.update(&epoch.to_be_bytes());
    let full = h.finalize();
    let mut out = String::with_capacity(32);
    for b in &full.as_bytes()[..16] {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// This epoch's label and the previous one's, current first.
///
/// Both, always, and for the reason the DHT does it: a node whose clock is an
/// hour out, or that looks up as the epoch turns, would otherwise be at a
/// rendezvous nobody else is at, with nothing in either log to say why.
pub fn current_labels(network: Network, unix_seconds: u64) -> [String; 2] {
    let epoch = epoch_of(unix_seconds);
    [
        label(network, epoch),
        label(network, epoch.saturating_sub(1)),
    ]
}

/// The Nostr identity this node posts as, derived from its veil identity.
///
/// DERIVED, not reused. The veil identity signs things that matter; a Nostr
/// key is a public handle posted to strangers' servers, and the two should not
/// be the same secret even though nothing here would leak it. Derivation also
/// means the node needs no extra key file, and that the same node reappears
/// under the same handle after a restart — which is what makes a relay REPLACE
/// its announcement instead of accumulating them.
pub fn identity_from_seed(veil_secret: &[u8]) -> SigningKey {
    // Counter loop: a 32-byte hash is a valid secp256k1 scalar with
    // overwhelming probability, but "overwhelming" is not "always", and a node
    // that panicked once in a billion starts would be impossible to diagnose.
    for counter in 0u32..1000 {
        let mut h = blake3::Hasher::new();
        h.update(DOMAIN);
        h.update(b"/identity");
        h.update(veil_secret);
        h.update(&counter.to_be_bytes());
        if let Ok(key) = SigningKey::from_bytes(h.finalize().as_bytes()) {
            return key;
        }
    }
    unreachable!("a thousand consecutive invalid scalars is not a thing that happens")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    const DAY: u64 = 24 * 60 * 60;

    #[test]
    fn the_two_networks_never_meet_and_the_label_moves_daily() {
        let mut seen = HashSet::new();
        for network in Network::ALL {
            for epoch in 0..8 {
                assert!(
                    seen.insert(label(*network, epoch)),
                    "{network:?} epoch {epoch} collides with another rendezvous"
                );
            }
        }
        assert_eq!(seen.len(), Network::ALL.len() * 8);

        let start = 1_700_000_000u64 / DAY * DAY;
        let first = label(Network::Production, epoch_of(start));
        for t in [start, start + 1, start + DAY / 2, start + DAY - 1] {
            assert_eq!(
                label(Network::Production, epoch_of(t)),
                first,
                "moved at {t}"
            );
        }
        assert_ne!(label(Network::Production, epoch_of(start + DAY)), first);
    }

    #[test]
    fn a_clock_that_is_wrong_by_hours_still_meets_everyone() {
        let boundary = 1_700_000_000u64 / DAY * DAY + DAY;
        let after = current_labels(Network::Production, boundary + 60);
        let before = current_labels(Network::Production, boundary - 3600);
        assert!(
            after.iter().any(|l| before.contains(l)),
            "a node an hour behind shares no rendezvous with one past the turn"
        );
        assert_eq!(
            current_labels(Network::Production, 0)[0],
            current_labels(Network::Production, 0)[1],
            "epoch zero must not underflow into a rendezvous nobody uses"
        );
    }

    #[test]
    fn the_label_is_something_a_relay_will_store() {
        // It travels inside JSON as a tag value. Raw bytes would be a tag some
        // relay refuses, and the failure would look like "nobody is there".
        let l = label(Network::Production, 42);
        assert_eq!(l.len(), 32);
        assert!(
            l.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())
        );
        // Consecutive epochs must not look related: adjacent labels would let
        // a watcher enumerate every past and future rendezvous from one.
        let a = label(Network::Production, 42);
        let b = label(Network::Production, 43);
        let differing = a.chars().zip(b.chars()).filter(|(x, y)| x != y).count();
        assert!(
            differing > 16,
            "consecutive labels differ in only {differing} of 32"
        );
    }

    #[test]
    fn the_nostr_handle_is_derived_stably_and_is_not_the_veil_key() {
        // Stable: the same node must come back as the same handle, or a relay
        // stores a new announcement each restart instead of replacing one.
        let seed = [7u8; 32];
        let a = identity_from_seed(&seed);
        let b = identity_from_seed(&seed);
        assert_eq!(a.verifying_key().to_bytes(), b.verifying_key().to_bytes());

        // Different nodes, different handles.
        let other = identity_from_seed(&[8u8; 32]);
        assert_ne!(
            a.verifying_key().to_bytes(),
            other.verifying_key().to_bytes()
        );

        // And NOT the veil secret itself: a public handle posted to strangers'
        // servers should not be the key that signs things that matter.
        assert_ne!(
            a.to_bytes().as_slice(),
            seed.as_slice(),
            "the Nostr key is the veil secret"
        );
    }
}
