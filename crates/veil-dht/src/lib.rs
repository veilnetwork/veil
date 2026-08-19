//! Veil-network Kademlia DHT.
//!
//! extraction. Pure routing/storage logic; upper-layer hooks
//! (frame dispatch, RTT/Vivaldi hints, metrics) come in through trait
//! surfaces declared [`traits`] so this crate doesn't depend on
//! `node::session`, `node::routing`, or `node::observability`.

#[cfg(test)]
pub mod bucket_pollution_sim;
#[cfg(test)]
pub mod churn_sim;
pub mod iterative;
pub mod kademlia;
pub mod lookup_cache;
pub mod network_querier;
pub mod republish;
pub mod routing;
pub mod shard;
pub mod store;
pub mod traits;
pub mod transport_cache;

pub use traits::{
    CoordinateOracle, DhtMetrics, DhtRuntimeConfig, FrameRouter, NetworkAuthGate, RttHint,
};

pub use iterative::{
    ALPHA, IterativeParams, LocalPeerQuerier, PeerQuerier, find_node_iterative,
    find_value_iterative,
};
pub use kademlia::{DhtValueSnapshot, KademliaError, KademliaService};
pub use lookup_cache::{DEFAULT_LOOKUP_CACHE_SIZE, DEFAULT_LOOKUP_CACHE_TTL, LookupCache};
pub use network_querier::NetworkPeerQuerier;
pub use routing::{Contact, K, RoutingTable};
pub use transport_cache::TransportCache;

#[cfg(test)]
mod tests {
    use super::*;
    use veil_proto::discovery::{FindValuePayload, StorePayload};

    /// tests use unsigned-STORE fixtures, so
    /// construct via the dev-flag path so the legacy fixtures keep
    /// working. Production paths use `KademliaService::new(...)`.
    fn test_kademlia(local_id: [u8; 32]) -> KademliaService {
        KademliaService::with_config(
            local_id,
            DhtRuntimeConfig {
                allow_unsigned_store: true,
                ..DhtRuntimeConfig::default()
            },
        )
    }

    /// The whole point of the bit: a peer that asked out disappears from
    /// every CANDIDATE list — what we hand walkers, whom we pick as store
    /// targets, whom we seed lookups from — while remaining in the table so
    /// it stays reachable.
    #[test]
    fn a_no_service_peer_is_never_a_candidate() {
        let svc = test_kademlia([0u8; 32]);
        let serving = Contact::with_caps(
            [1u8; 32],
            "tcp://serves:9000",
            veil_types::DiscoveryMode::Public,
            true,
        );
        let quiet = Contact::with_caps(
            [2u8; 32],
            "tcp://quiet:9000",
            veil_types::DiscoveryMode::Public,
            false,
        );
        svc.add_contact(serving);
        svc.add_contact(quiet);
        assert_eq!(
            svc.routing_table_size(),
            2,
            "both stay in the table — eviction would break reachability"
        );

        let target = [3u8; 32];
        assert!(
            !svc.find_closest_nodes(&target, 8).contains(&[2u8; 32]),
            "never a next-hop or replication target"
        );
        assert!(
            !svc.find_closest_public_node_ids(&target, 8)
                .contains(&[2u8; 32]),
            "never handed to a walker as a closer node"
        );
        assert!(
            !svc.find_closest_with_transport(&target, 8)
                .iter()
                .any(|(id, _)| *id == [2u8; 32]),
            "never a replication target in the subnet-diversity path"
        );
        assert!(
            !svc.find_closest_contacts(&target, 8)
                .iter()
                .any(|c| c.node_id == [2u8; 32]),
            "never a seed for an iterative walk"
        );

        // And the serving peer is still picked, so the filter is not just
        // emptying every list.
        assert!(svc.find_closest_nodes(&target, 8).contains(&[1u8; 32]));
        assert!(
            svc.find_closest_public_node_ids(&target, 8)
                .contains(&[1u8; 32])
        );

        // The skip is COUNTED. A filter with no instrument is one nobody can
        // tell apart from a no-op — which is exactly how the byte budget
        // before this looked healthy by its own counters while changing the
        // traffic by nothing.
        assert!(
            svc.no_dht_service_skips() > 0,
            "every path above passed over the quiet peer and none said so"
        );
    }

    /// Promotion must not undo what the handshake stamped.
    ///
    /// A pending contact is a THIRD PARTY's word: id and transport, default
    /// capabilities, because nobody may speak for a peer's own preferences.
    /// Promoting it over a verified entry silently reverted both stamps —
    /// `discovery_mode` and `no_dht_service` — and nothing could see it until
    /// the skip counter gave the second one a number. Found live: the peer
    /// advertised `dht_service=false`, the log said so, and the replication
    /// still fanned out to it.
    #[test]
    fn promotion_does_not_overwrite_handshake_capabilities() {
        let svc = test_kademlia([0u8; 32]);
        let quiet = [9u8; 32];

        // What a third party told us, and what the peer itself then said.
        svc.add_contact_unverified_from([1u8; 32], Contact::new(quiet, "tcp://gossip:9000"));
        svc.add_contact_trusted(Contact::with_caps(
            quiet,
            "quic://real:5601",
            veil_types::DiscoveryMode::Public,
            false,
        ));
        assert!(svc.promote_contact_if_pending(&quiet));

        assert!(
            !svc.find_closest_nodes(&[3u8; 32], 8).contains(&quiet),
            "promotion put the peer back into candidate selection"
        );
        assert!(svc.no_dht_service_skips() > 0);
    }

    /// The counter must not fire for peers that are simply not the closest —
    /// only for ones actively passed over. A count that rose on ordinary
    /// selection would be noise indistinguishable from the signal.
    #[test]
    fn nothing_is_counted_when_everyone_serves() {
        let svc = test_kademlia([0u8; 32]);
        svc.add_contact(Contact::new([1u8; 32], "tcp://a:9000"));
        svc.add_contact(Contact::new([2u8; 32], "tcp://b:9000"));
        let _ = svc.find_closest_nodes(&[3u8; 32], 8);
        let _ = svc.find_closest_public_node_ids(&[3u8; 32], 8);
        assert_eq!(svc.no_dht_service_skips(), 0);
    }

    #[test]
    fn dht_store_lookup_delete_integration() {
        let svc = test_kademlia([0u8; 32]);

        // Populate routing table
        svc.add_contact(Contact::new([1u8; 32], "tcp://peer1:9000"));
        svc.add_contact(Contact::new([2u8; 32], "tcp://peer2:9000"));
        assert_eq!(svc.routing_table_size(), 2);

        // Store and retrieve a value
        let key = [42u8; 32];
        svc.handle_store(StorePayload::unsigned(key, b"hello".to_vec()))
            .unwrap();
        assert_eq!(svc.stored_keys(), 1);

        let resp = svc.handle_find_value(FindValuePayload { key });
        assert!(
            matches!(resp, veil_proto::discovery::FindValueResponse::Value(v) if v == b"hello")
        );

        // Remove contact
        svc.remove_contact(&[1u8; 32]);
        assert_eq!(svc.routing_table_size(), 1);
    }

    #[test]
    fn gateway_can_participate_in_dht() {
        let svc = test_kademlia([10u8; 32]);
        svc.handle_store(StorePayload::unsigned([1u8; 32], b"gw".to_vec()))
            .unwrap();
        assert_eq!(svc.stored_keys(), 1);
    }

    #[test]
    fn leaf_participate_false_cannot_store() {
        let mut svc = test_kademlia([0u8; 32]);
        svc.set_participate(false);
        let err = svc
            .handle_store(StorePayload::unsigned([0u8; 32], vec![]))
            .unwrap_err();
        assert_eq!(err, KademliaError::DhtParticipationDisabled);
    }

    /// Stage 11e: handle_store routes unsigned legacy STOREs through the
    /// shared `ORIGIN_UNSIGNED` bucket and enforces the per-origin cap
    /// across all unsigned STOREs collectively.
    #[test]
    fn handle_store_unsigned_shares_bucket_under_per_origin_cap() {
        let svc = KademliaService::with_config(
            [0u8; 32],
            DhtRuntimeConfig {
                allow_unsigned_store: true,
                per_origin_max_bytes: Some(150),
                ..DhtRuntimeConfig::default()
            },
        );
        // Three 50-byte unsigned STOREs collectively occupy 150 bytes →
        // exactly at the cap.
        svc.handle_store(StorePayload::unsigned([1u8; 32], vec![0u8; 50]))
            .unwrap();
        svc.handle_store(StorePayload::unsigned([2u8; 32], vec![0u8; 50]))
            .unwrap();
        svc.handle_store(StorePayload::unsigned([3u8; 32], vec![0u8; 50]))
            .unwrap();
        // 4th unsigned STORE: pushes bucket to 200 > 150 → refused.
        let err = svc
            .handle_store(StorePayload::unsigned([4u8; 32], vec![0u8; 50]))
            .unwrap_err();
        assert_eq!(err, KademliaError::PerOriginByteCapExceeded);
        assert_eq!(svc.stored_keys(), 3);
    }

    /// Stage 11e: per-origin cap on signed STOREs isolates noisy signers
    /// from polite ones — a signer that exhausts its bucket cannot
    /// crowd out a separate signer's records.
    #[test]
    fn handle_store_signed_isolates_origins_under_per_origin_cap() {
        use ed25519_dalek::{Signer as _, SigningKey};
        use rand_core::OsRng;
        use veil_proto::discovery::StorePayload;

        let svc = KademliaService::with_config(
            [0u8; 32],
            DhtRuntimeConfig {
                allow_unsigned_store: false,
                per_origin_max_bytes: Some(120),
                ..DhtRuntimeConfig::default()
            },
        );
        let alice_sk = SigningKey::generate(&mut OsRng);
        let alice_pk: [u8; 32] = *alice_sk.verifying_key().as_bytes();
        let alice_key: [u8; 32] = *blake3::hash(&alice_pk).as_bytes();
        let bob_sk = SigningKey::generate(&mut OsRng);
        let bob_pk: [u8; 32] = *bob_sk.verifying_key().as_bytes();
        let bob_key: [u8; 32] = *blake3::hash(&bob_pk).as_bytes();

        let sign_store =
            |sk: &SigningKey, pk: [u8; 32], key: [u8; 32], value: Vec<u8>| -> StorePayload {
                let mut to_sign = Vec::with_capacity(32 + value.len());
                to_sign.extend_from_slice(&key);
                to_sign.extend_from_slice(&value);
                let sig = sk.sign(&to_sign).to_bytes();
                StorePayload {
                    key,
                    value,
                    ed25519_pubkey: Some(pk),
                    ed25519_sig: Some(sig),
                }
            };

        // Alice fills her bucket to the cap.
        svc.handle_store(sign_store(&alice_sk, alice_pk, alice_key, vec![0u8; 120]))
            .unwrap();
        // Alice tries to overwrite with a larger value — refused by cap.
        // (The overwrite path refunds the old bytes; 121 > 120 still fails.)
        let err = svc
            .handle_store(sign_store(&alice_sk, alice_pk, alice_key, vec![0u8; 121]))
            .unwrap_err();
        assert_eq!(err, KademliaError::PerOriginByteCapExceeded);
        // Bob's bucket is untouched: he can fill to his own cap.
        svc.handle_store(sign_store(&bob_sk, bob_pk, bob_key, vec![0u8; 120]))
            .unwrap();
        assert_eq!(svc.stored_keys(), 2);
    }
}
