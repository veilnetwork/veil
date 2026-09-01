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

/// The Nostr identity this node posts as this epoch, derived from its veil
/// identity and the epoch together.
///
/// DERIVED, not reused. The veil identity signs things that matter; a Nostr
/// key is a public handle posted to strangers' servers, and the two should not
/// be the same secret even though nothing here would leak it. Derivation also
/// means the node needs no extra key file.
///
/// PER EPOCH, and that is not a detail. [`label`] moves every day so that
/// nobody can watch one address and see who keeps arriving; a constant author
/// key would hand back exactly what the rotation takes away, because a relay
/// will happily serve every event by an author forever. An observer who sees
/// this node once could then follow it across every epoch and every change of
/// address, which is a better handle on it than the seed list it replaced.
///
/// Nothing is lost by moving it: peers filter on the label, never on the
/// author, and within one epoch the key is fixed — so a node that restarts
/// still REPLACES its own announcement rather than accumulating them, which is
/// the one property the stable key was there for.
pub fn identity_from_seed(veil_secret: &[u8], epoch: u64) -> SigningKey {
    // Counter loop: a 32-byte hash is a valid secp256k1 scalar with
    // overwhelming probability, but "overwhelming" is not "always", and a node
    // that panicked once in a billion starts would be impossible to diagnose.
    for counter in 0u32..1000 {
        let mut h = blake3::Hasher::new();
        h.update(DOMAIN);
        h.update(b"/identity");
        h.update(veil_secret);
        h.update(&epoch.to_be_bytes());
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
    fn the_author_moves_with_the_label_and_holds_still_inside_an_epoch() {
        // The label rotates daily so nobody can watch one rendezvous and see
        // who keeps arriving. An author key that did NOT rotate would give
        // that back in full: relays serve every event by an author on request,
        // so one sighting would follow this node across every epoch and every
        // address it ever has.
        let seed = [7u8; 32];
        let mut authors = HashSet::new();
        for epoch in 0..8u64 {
            let a = hex_pubkey(&identity_from_seed(&seed, epoch));
            assert!(
                authors.insert(a),
                "epoch {epoch} posts under an author some other epoch also uses; \
                 the daily label rotation is then decorative"
            );
        }

        // ...and STILL for the length of one, or a node that restarts posts a
        // second announcement instead of replacing its own.
        assert_eq!(
            hex_pubkey(&identity_from_seed(&seed, 3)),
            hex_pubkey(&identity_from_seed(&seed, 3)),
            "the author is not stable within an epoch; announcements accumulate"
        );

        // Two nodes are two authors, in the same epoch.
        assert_ne!(
            hex_pubkey(&identity_from_seed(&seed, 3)),
            hex_pubkey(&identity_from_seed(&[9u8; 32], 3)),
            "two different veil identities share a Nostr handle"
        );
    }

    fn hex_pubkey(key: &SigningKey) -> String {
        key.verifying_key()
            .to_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

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
    fn the_nostr_handle_is_not_the_veil_key() {
        // Stability and distinctness live in the rotation guard above; the
        // claim here is the one that would be a leak rather than a nuisance.
        // A public handle posted to strangers' servers must not be the key
        // that signs things that matter.
        let seed = [7u8; 32];
        for epoch in 0..4u64 {
            assert_ne!(
                identity_from_seed(&seed, epoch).to_bytes().as_slice(),
                seed.as_slice(),
                "epoch {epoch} posts under the veil secret itself"
            );
        }
    }
}
