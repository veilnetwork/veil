//! Which addresses a rendezvous ad may legitimately be published under.
//!
//! One question, asked by two places that must agree: the publisher's own
//! freshness probe, which re-signs when the ad it finds is not a good one, and
//! the sender's resolver, which drops an ad it cannot tie to the receiver it
//! asked for. Two copies of this rule drifting apart would have a node
//! re-publishing an ad every tick that no sender accepts, or the reverse.

use std::sync::Arc;

use veil_anonymity::rendezvous::RendezvousAd;
use veil_dht::KademliaService;

/// Is this ad tied to the address it names?
///
/// Two ways, and the ad does not say which — it carries no index, only the
/// issuer key, so the answer is looked up rather than claimed:
///
/// * `BLAKE3(issuer_pk) == receiver_node_id` — the signer IS the address. That
///   is every legacy node and every identity whose device key is its master,
///   and it needs nothing off the network.
/// * otherwise the identity document at `receiver_node_id` must name the
///   issuer among its device keys. A hybrid identity's address is the hash of
///   a 929-byte master that no device key can reproduce, so this is the ONLY
///   way such a receiver is reachable at the address its contacts know.
///
/// The document is read from the LOCAL shard, on purpose: the callers are
/// synchronous filters and a resolve must not block on a DHT walk. A node that
/// does not hold the document answers no and drops the ad — the same
/// conservative outcome as before delegation existed.
pub(crate) fn ad_binding_ok(dht: &Arc<KademliaService>, ad: &RendezvousAd) -> bool {
    if veil_anonymity::rendezvous::verify_rendezvous_ad(ad).is_ok() {
        return true;
    }
    let Some(keys) = identity_device_keys(dht, &ad.receiver_node_id) else {
        return false;
    };
    veil_anonymity::rendezvous::verify_rendezvous_ad_delegated(ad, &ad.receiver_node_id, &keys)
        .is_ok()
}

/// The device pubkeys a VERIFIED identity document names for `node_id`.
///
/// The full verifier ladder, clock included: this document came off the
/// network, so an expired delegation must not keep a receiver advertising.
fn identity_device_keys(dht: &Arc<KademliaService>, node_id: &[u8; 32]) -> Option<Vec<Vec<u8>>> {
    let key = veil_proto::identity_document::IdentityDocument::dht_key(node_id);
    let bytes = dht.get_local(&key)?;
    let doc = veil_proto::identity_document::IdentityDocument::decode(&bytes).ok()?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    veil_identity::verify::verify_identity_document(&doc, now).ok()?;
    Some(doc.identity_keys.into_iter().map(|k| k.pubkey).collect())
}

/// Every address this node must be findable at as a RECEIVER.
///
/// The device transport id is always one of them: it is what every sender
/// running today's code looks up, and what an ad bound the strict way proves.
/// When a sovereign identity is loaded and its address differs — a hybrid
/// master, or a device provisioned from a recovery certificate — that address
/// is the second, because it is the one the invite hands out and therefore the
/// only one a contact ever asks for.
///
/// Publishing at BOTH is what makes the change cost nobody reachability: an
/// un-updated sender keeps resolving the device-bound ad it can verify, and an
/// updated one finds the identity-bound ad where it actually looks. The first
/// address can be retired once no sender resolves by it.
pub(crate) fn receiver_addresses(
    device: [u8; 32],
    sovereign: &super::identity_state::SovereignIdentityCell,
) -> Vec<[u8; 32]> {
    match sovereign.get() {
        Some(sov) if *sov.node_id() != device => vec![device, *sov.node_id()],
        _ => vec![device],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use veil_anonymity::rendezvous::{
        RendezvousPublisherEntry, decode_rendezvous_ad, rendezvous_ad_dht_key, verify_rendezvous_ad,
    };
    use veil_observability::NodeLogger;

    /// Both addresses, and only when they are two.
    ///
    /// The device id must stay in the list: it is what every sender running
    /// today's code resolves by, and dropping it would take reachability away
    /// from all of them on the day this ships. The identity address joins it
    /// only when the two differ — for a legacy or standalone node they are one
    /// value, and publishing the same ad twice under one key is work for
    /// nothing.
    #[test]
    fn a_sovereign_receiver_advertises_at_both_addresses() {
        use crate::runtime::identity_state::SovereignIdentityCell;

        let dir = std::env::temp_dir().join(format!(
            "rzv-addrs-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let out = veil_identity::sovereign_flow::create_identity(
            veil_identity::sovereign_flow::CreateIdentityOptions {
                veil_dir: dir.clone(),
                save_encrypted_with_password: None,
                argon2_params_override: Some((8, 1, 1)),
                extra_entropy: None,
                instance_label: "rzv".to_string(),
                pow_difficulty: 0,
                issued_at_unix: now,
                valid_until_unix: now + 7 * 24 * 3600,
                algo: veil_types::SignatureAlgorithm::Ed25519,
            },
        )
        .expect("create_identity");
        std::fs::write(
            dir.join("device_identity_sk.bin"),
            out.identity_sk_seed.as_array(),
        )
        .unwrap();
        let sov = std::sync::Arc::new(
            veil_identity::sovereign::SovereignIdentity::load_from_dir(&dir)
                .expect("the identity just written must load"),
        );

        let device = [0x11u8; 32];
        assert_ne!(device, *sov.node_id());

        // No sovereign identity: unchanged, one address.
        let empty = SovereignIdentityCell::new(None);
        assert_eq!(receiver_addresses(device, &empty), vec![device]);

        // With one whose address differs: both, device FIRST.
        let cell = SovereignIdentityCell::new(Some(std::sync::Arc::clone(&sov)));
        assert_eq!(
            receiver_addresses(device, &cell),
            vec![device, *sov.node_id()],
            "a sender on today's code resolves by the device id and must keep \
             finding an ad there",
        );

        // And when the two coincide — the standalone shape — one address, not
        // the same ad written twice.
        assert_eq!(
            receiver_addresses(*sov.node_id(), &cell),
            vec![*sov.node_id()]
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A device of an identity may advertise at the IDENTITY's address.
    ///
    /// The strict binding is `BLAKE3(issuer_pk) == receiver_node_id`, which no
    /// device key of a real identity satisfies: the address is the hash of the
    /// MASTER, and `create_identity` mints a separate device subkey. So a
    /// receiver could publish only at its device address, while every contact
    /// looks it up by the identity address the invite carries — an ad at an
    /// address nobody asks for, and inbound delivery with nowhere to land.
    ///
    /// The control is the whole point of the test: WITHOUT the document, the
    /// same ad is refused. Nothing is waved through; the document is what
    /// proves the binding, and a node that cannot read one admits nothing.
    #[test]
    fn a_device_may_advertise_at_its_identitys_address() {
        use std::sync::{Arc, Mutex};

        let dir = std::env::temp_dir().join(format!(
            "rzv-binding-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let out = veil_identity::sovereign_flow::create_identity(
            veil_identity::sovereign_flow::CreateIdentityOptions {
                veil_dir: dir.clone(),
                save_encrypted_with_password: None,
                argon2_params_override: Some((8, 1, 1)),
                extra_entropy: None,
                instance_label: "rzv".to_string(),
                pow_difficulty: 0,
                issued_at_unix: now,
                valid_until_unix: now + 7 * 24 * 3600,
                algo: veil_types::SignatureAlgorithm::Ed25519,
            },
        )
        .expect("create_identity");

        // The device key the identity actually runs on — a SUBKEY, filed in
        // the document, whose hash is not the address.
        let seed: [u8; 32] = *out.identity_sk_seed.as_array();
        let device_sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        let device_pk = device_sk.verifying_key().to_bytes();
        let device_identity = crate::local_identity::HandshakeIdentity {
            algo: veil_cfg::SignatureAlgorithm::Ed25519,
            public_key: base64::engine::general_purpose::STANDARD.encode(device_pk),
            private_key: base64::engine::general_purpose::STANDARD.encode(seed),
            nonce: "AAAA".to_owned(),
            node_id: veil_cfg::NodeId::from_public_key(
                veil_cfg::SignatureAlgorithm::Ed25519,
                &base64::engine::general_purpose::STANDARD.encode(device_pk),
            )
            .unwrap(),
        };
        assert_ne!(
            *device_identity.node_id.as_bytes(),
            out.node_id,
            "fixture is vacuous unless the device and the identity are two addresses",
        );

        let dht = Arc::new(veil_dht::KademliaService::new(
            *device_identity.node_id.as_bytes(),
        ));
        let x25519_sk = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
        let logger = Arc::new(NodeLogger::new_noop());
        let entries = Arc::new(Mutex::new(vec![RendezvousPublisherEntry {
            rendezvous_node_id: [0xCC; 32],
            auth_cookie: [0xDD; 16],
            validity_window_secs: 3600,
            push_envelope: Vec::new(),
            wake_hmac_envelope: Vec::new(),
            rendezvous_kem_algo: 0,
            rendezvous_kem_pk: Vec::new(),
            ephemeral_ad_identity: None,
            rendezvous_kem_valid_until_unix: 0,
        }]));

        let published = crate::runtime::NodeRuntime::tick_publish_rendezvous_ads(
            &entries,
            &x25519_sk,
            &device_identity,
            &out.node_id,
            &dht,
            &logger,
            None,
        );
        assert_eq!(
            published, 1,
            "the ad must be published at the address asked for"
        );

        let bytes = dht
            .get_local(&rendezvous_ad_dht_key(&out.node_id))
            .expect("an ad at the IDENTITY address");
        let ad = decode_rendezvous_ad(&bytes).expect("decode");
        assert_eq!(ad.receiver_node_id, out.node_id);
        assert!(
            verify_rendezvous_ad(&ad).is_err(),
            "the strict binding cannot hold here — if it does, the fixture is \
             not the case this is about",
        );

        // Control FIRST: with no document to read, the ad is refused.
        assert!(
            !ad_binding_ok(&dht, &ad),
            "without the identity document there is no binding to check",
        );

        // And with the document the identity itself published, it is admitted.
        dht.store_local(
            veil_proto::identity_document::IdentityDocument::dht_key(&out.node_id),
            out.document.encode(),
        );
        assert!(
            ad_binding_ok(&dht, &ad),
            "the document names this device key, which is what ties it to the \
             address",
        );

        // A LOCATION-ANONYMOUS entry belongs to the device pass alone. Its ad
        // is keyed and signed under a per-service PSEUDO identity that has
        // nothing to do with this address — publishing it once per address
        // would write the same key twice, and the pseudo identity exists
        // precisely so the ad is NOT linked to the service's sovereign
        // address.
        {
            use veil_anonymity::rendezvous::EphemeralAdIdentity;
            let eph_sk = ed25519_dalek::SigningKey::from_bytes(&[0x5E; 32]);
            let eph_pk = eph_sk.verifying_key().to_bytes();
            let pseudo = *blake3::hash(&eph_pk).as_bytes();
            let eph_entries = Arc::new(Mutex::new(vec![RendezvousPublisherEntry {
                rendezvous_node_id: [0xCC; 32],
                auth_cookie: [0xDD; 16],
                validity_window_secs: 3600,
                push_envelope: Vec::new(),
                wake_hmac_envelope: Vec::new(),
                rendezvous_kem_algo: 0,
                rendezvous_kem_pk: Vec::new(),
                ephemeral_ad_identity: Some(EphemeralAdIdentity {
                    pseudo_node_id: pseudo,
                    public_key: base64::engine::general_purpose::STANDARD.encode(eph_pk),
                    private_key: zeroize::Zeroizing::new(
                        base64::engine::general_purpose::STANDARD.encode(eph_sk.to_bytes()),
                    ),
                    algo: veil_cfg::SignatureAlgorithm::Ed25519,
                }),
                rendezvous_kem_valid_until_unix: 0,
            }]));
            let fresh = Arc::new(veil_dht::KademliaService::new(
                *device_identity.node_id.as_bytes(),
            ));
            // The identity pass FIRST, on an empty store: a second pass over a
            // store that already holds the ad publishes nothing anyway, because
            // the freshness probe skips it — so this order is what makes the
            // assertion about the guard rather than about freshness.
            assert_eq!(
                crate::runtime::NodeRuntime::tick_publish_rendezvous_ads(
                    &eph_entries,
                    &x25519_sk,
                    &device_identity,
                    &out.node_id,
                    &fresh,
                    &logger,
                    None,
                ),
                0,
                "the identity pass must leave a location-anonymous ad alone",
            );
            assert_eq!(
                crate::runtime::NodeRuntime::tick_publish_rendezvous_ads(
                    &eph_entries,
                    &x25519_sk,
                    &device_identity,
                    device_identity.node_id.as_bytes(),
                    &fresh,
                    &logger,
                    None,
                ),
                1,
                "and the device pass still publishes it — or the assertion \
                 above is about an entry nothing would publish",
            );
        }

        let _ = std::fs::remove_dir_all(&dir);
    }
}
