//! Authenticated anonymous delivery — sign / verify (v1).
//!
//! Pairs with [`veil_proto::AuthAppDeliver`]. The onion transport hides the
//! sender's network LOCATION from every relay; this layer lets the RECIPIENT
//! cryptographically verify WHO sent the message — the property meta-E2E and the
//! KEM-seal `x3dh.rs` do NOT provide (a KEM proves nothing about origin).
//!
//! - The sender signs [`AuthAppDeliver::signing_bytes`] with its active identity
//!   subkey ([`crate::sovereign::SovereignIdentity::sign_auth_deliver`]).
//! - The recipient calls [`verify_auth_deliver`] with the sender's resolved
//!   [`IdentityDocument`] (the caller resolves it — contact cache → DHT — and the
//!   resolve already established `BLAKE3(master) == node_id` + document
//!   signature). This function adds the per-message checks: recipient binding,
//!   sender↔doc match, freshness, subkey validity, and the signature.
//!
//! Anti-replay (the per-sender `nonce` window) is the caller's responsibility —
//! it is stateful and lives at the dispatcher final-hop (next brick).

use base64::Engine as _;
use veil_crypto::verify_message;
use veil_proto::AuthAppDeliver;
use veil_proto::identity_document::{ALGO_ED25519, ALGO_FALCON512, IdentityDocument};
use veil_types::SignatureAlgorithm;

/// Default freshness window for an authenticated delivery (seconds). Bounds the
/// per-sender replay-cache the recipient must keep, and the clock-skew tolerance.
pub const DEFAULT_AUTH_DELIVER_FRESHNESS_SECS: u64 = 300;

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum AuthDeliverError {
    #[error("authenticated delivery not addressed to this node")]
    WrongRecipient,
    #[error("sender_node_id does not match the resolved identity document")]
    SenderMismatch,
    #[error("timestamp {timestamp} outside freshness window (now={now}, window={window}s)")]
    Stale {
        timestamp: u64,
        now: u64,
        window: u64,
    },
    #[error("sig_key_idx {0} out of range for the identity document")]
    BadKeyIndex(u16),
    #[error("signing subkey not valid at this time")]
    SubkeyNotValid,
    #[error("unsupported subkey algo {0} (v1 accepts Ed25519 / Falcon-512)")]
    UnsupportedAlgo(u8),
    #[error("signature verification failed")]
    BadSignature,
    #[error("replayed authenticated delivery (sender+nonce already seen)")]
    Replay,
}

/// FIFO cap on the per-sender replay window. ~65k × 24 B ≈ 1.5 MiB; an attacker
/// pumping unique nonces can only force-evict the OLDEST entries, never a
/// just-recorded one.
pub const DEFAULT_AUTH_DELIVER_REPLAY_CAP: usize = 65_536;

/// Bounded per-recipient replay cache for authenticated deliveries, keyed on
/// `BLAKE3(sender_node_id || nonce)`. Entries expire after `ttl_secs` (set to
/// the freshness window — a replay older than that is already rejected by the
/// freshness check in [`verify_auth_deliver`], so we never need to remember it
/// longer). Same insertion-ordered queue + set shape as the rendezvous
/// `IntroduceReplayCache`. The caller verifies FIRST, then records — so a forged
/// envelope never pollutes the cache.
pub struct AuthDeliverReplayCache {
    seen: std::sync::Mutex<ReplayState>,
    ttl_secs: u64,
    cap: usize,
}

#[derive(Default)]
struct ReplayState {
    /// Insertion-ordered `(fingerprint, expiry_unix)` — front is oldest.
    queue: std::collections::VecDeque<([u8; 16], u64)>,
    /// O(1) membership.
    set: std::collections::HashSet<[u8; 16]>,
}

impl AuthDeliverReplayCache {
    /// Cache with the default freshness-window TTL and capacity.
    pub fn new() -> Self {
        Self::with_params(
            DEFAULT_AUTH_DELIVER_FRESHNESS_SECS,
            DEFAULT_AUTH_DELIVER_REPLAY_CAP,
        )
    }

    /// Cache with explicit TTL + capacity.
    pub fn with_params(ttl_secs: u64, cap: usize) -> Self {
        Self {
            seen: std::sync::Mutex::new(ReplayState::default()),
            ttl_secs,
            cap,
        }
    }

    fn fingerprint(sender_node_id: &[u8; 32], nonce: u64) -> [u8; 16] {
        let mut h = blake3::Hasher::new();
        h.update(b"veil.auth-deliver.replay.v1");
        h.update(sender_node_id);
        h.update(&nonce.to_be_bytes());
        let mut fp = [0u8; 16];
        fp.copy_from_slice(&h.finalize().as_bytes()[..16]);
        fp
    }

    /// Record `(sender_node_id, nonce)` as seen, or return
    /// [`AuthDeliverError::Replay`] if it already was within the TTL. Call ONLY
    /// after [`verify_auth_deliver`] has accepted the message.
    pub fn check_and_record(
        &self,
        sender_node_id: &[u8; 32],
        nonce: u64,
        now_unix: u64,
    ) -> Result<(), AuthDeliverError> {
        let fp = Self::fingerprint(sender_node_id, nonce);
        let mut g = self.seen.lock().unwrap_or_else(|p| p.into_inner());
        // Lazy GC from the front (uniform TTL → front is oldest expiry).
        while let Some(&(fp_old, exp)) = g.queue.front() {
            if now_unix < exp {
                break;
            }
            g.queue.pop_front();
            g.set.remove(&fp_old);
        }
        if g.set.contains(&fp) {
            return Err(AuthDeliverError::Replay);
        }
        // FIFO cap-evict (drop the oldest, never the just-recorded entry).
        if g.set.len() >= self.cap
            && let Some((fp_old, _)) = g.queue.pop_front()
        {
            g.set.remove(&fp_old);
        }
        g.queue
            .push_back((fp, now_unix.saturating_add(self.ttl_secs)));
        g.set.insert(fp);
        Ok(())
    }
}

impl Default for AuthDeliverReplayCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Verify an [`AuthAppDeliver`] at the recipient. Pure (no replay state).
///
/// `sender_doc` MUST be the verified IdentityDocument of `p.sender_node_id`
/// (caller resolves it). `self_node_id` is the recipient's own node_id.
pub fn verify_auth_deliver(
    p: &AuthAppDeliver,
    sender_doc: &IdentityDocument,
    self_node_id: &[u8; 32],
    now_unix: u64,
    freshness_window_secs: u64,
) -> Result<(), AuthDeliverError> {
    // Bound to THIS recipient — a relay cannot re-target the envelope.
    if &p.dst_node_id != self_node_id {
        return Err(AuthDeliverError::WrongRecipient);
    }
    // The claimed sender must match the document we resolved for it.
    if p.sender_node_id != sender_doc.node_id {
        return Err(AuthDeliverError::SenderMismatch);
    }
    // Freshness (both directions — future timestamps are clock skew).
    if now_unix.abs_diff(p.timestamp) > freshness_window_secs {
        return Err(AuthDeliverError::Stale {
            timestamp: p.timestamp,
            now: now_unix,
            window: freshness_window_secs,
        });
    }
    let subkey = sender_doc
        .identity_keys
        .get(p.sig_key_idx as usize)
        .ok_or(AuthDeliverError::BadKeyIndex(p.sig_key_idx))?;
    if now_unix < subkey.valid_from_unix || now_unix > subkey.valid_until_unix {
        return Err(AuthDeliverError::SubkeyNotValid);
    }
    let algo = match subkey.algo {
        ALGO_ED25519 => SignatureAlgorithm::Ed25519,
        ALGO_FALCON512 => SignatureAlgorithm::Falcon512,
        other => return Err(AuthDeliverError::UnsupportedAlgo(other)),
    };
    // `verify_message` takes a base64 pubkey (same encoding as IdentityConfig).
    let pk_b64 = base64::engine::general_purpose::STANDARD.encode(&subkey.pubkey);
    verify_message(algo, &pk_b64, &p.signing_bytes(), &p.signature)
        .map_err(|_| AuthDeliverError::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use veil_crypto::{generate_keypair, sign_message};
    use veil_proto::identity_document::IdentityKey;

    const NOW: u64 = 1_700_000_000;

    #[test]
    fn replay_cache_accepts_once_then_rejects_duplicate() {
        let cache = AuthDeliverReplayCache::new();
        let alice = [0xAA; 32];
        assert_eq!(cache.check_and_record(&alice, 1, NOW), Ok(()));
        // Same (sender, nonce) → replay.
        assert_eq!(
            cache.check_and_record(&alice, 1, NOW),
            Err(AuthDeliverError::Replay)
        );
        // Different nonce, same sender → ok.
        assert_eq!(cache.check_and_record(&alice, 2, NOW), Ok(()));
        // Same nonce, different sender → ok (key includes sender).
        assert_eq!(cache.check_and_record(&[0xBB; 32], 1, NOW), Ok(()));
    }

    #[test]
    fn replay_cache_forgets_after_ttl() {
        let cache = AuthDeliverReplayCache::with_params(300, 1024);
        let alice = [0xAA; 32];
        assert_eq!(cache.check_and_record(&alice, 7, NOW), Ok(()));
        // Within TTL → still a replay.
        assert_eq!(
            cache.check_and_record(&alice, 7, NOW + 299),
            Err(AuthDeliverError::Replay)
        );
        // Past TTL → the entry is GC'd, so it is accepted again. (Freshness in
        // verify_auth_deliver independently rejects a stale timestamp; this only
        // governs the cache's memory window.)
        assert_eq!(cache.check_and_record(&alice, 7, NOW + 301), Ok(()));
    }

    #[test]
    fn replay_cache_cap_evicts_fifo_oldest() {
        let cache = AuthDeliverReplayCache::with_params(10_000, 2);
        let alice = [0xAA; 32];
        assert_eq!(cache.check_and_record(&alice, 1, NOW), Ok(()));
        assert_eq!(cache.check_and_record(&alice, 2, NOW), Ok(()));
        // Inserting a 3rd over cap=2 evicts the OLDEST (nonce 1).
        assert_eq!(cache.check_and_record(&alice, 3, NOW), Ok(()));
        // nonce 1 was evicted → accepted again (not a replay).
        assert_eq!(cache.check_and_record(&alice, 1, NOW), Ok(()));
        // nonce 3 is still present → replay.
        assert_eq!(
            cache.check_and_record(&alice, 3, NOW),
            Err(AuthDeliverError::Replay)
        );
    }

    /// Build a synthetic single-Ed25519-subkey IdentityDocument + a matching
    /// signed AuthAppDeliver. Returns (doc, payload, self_node_id, sender_node_id).
    fn signed_fixture() -> (IdentityDocument, AuthAppDeliver, [u8; 32], [u8; 32]) {
        let kp = generate_keypair(SignatureAlgorithm::Ed25519);
        let pk_bytes = base64::engine::general_purpose::STANDARD
            .decode(&kp.public_key)
            .unwrap();
        let mut sender_node_id = [0u8; 32];
        sender_node_id.copy_from_slice(blake3::hash(&pk_bytes).as_bytes());
        let self_node_id = [0xBB; 32]; // recipient

        let doc = IdentityDocument {
            node_id: sender_node_id,
            issued_at_unix: NOW - 10,
            valid_until_unix: NOW + 86_400,
            master_pubkey: pk_bytes.clone(),
            master_algo: ALGO_ED25519,
            identity_keys: vec![IdentityKey {
                algo: ALGO_ED25519,
                pubkey: pk_bytes,
                device_id: [0u8; 32],
                valid_from_unix: NOW - 10,
                valid_until_unix: NOW + 86_400,
                master_sig: vec![0u8; 64],
            }],
            sig_key_idx: 0,
            document_sig: vec![0u8; 64],
        };

        let mut p = AuthAppDeliver {
            version: AuthAppDeliver::VERSION,
            sender_node_id,
            sig_key_idx: 0,
            timestamp: NOW,
            nonce: 0xDEAD_BEEF,
            dst_node_id: self_node_id,
            app_id: [0xCC; 32],
            endpoint_id: 7,
            data: b"authentic hello".to_vec(),
            signature: Vec::new(),
        };
        p.signature = sign_message(
            SignatureAlgorithm::Ed25519,
            &kp.public_key,
            &kp.private_key,
            &p.signing_bytes(),
        )
        .unwrap();
        (doc, p, self_node_id, sender_node_id)
    }

    #[test]
    fn verify_accepts_a_genuine_signed_delivery() {
        let (doc, p, self_id, _) = signed_fixture();
        assert_eq!(
            verify_auth_deliver(&p, &doc, &self_id, NOW, DEFAULT_AUTH_DELIVER_FRESHNESS_SECS),
            Ok(())
        );
    }

    #[test]
    fn verify_rejects_tampered_data() {
        let (doc, mut p, self_id, _) = signed_fixture();
        p.data.push(0x00); // signature no longer covers the data
        assert_eq!(
            verify_auth_deliver(&p, &doc, &self_id, NOW, DEFAULT_AUTH_DELIVER_FRESHNESS_SECS),
            Err(AuthDeliverError::BadSignature),
        );
    }

    #[test]
    fn verify_rejects_retargeted_or_wrong_sender() {
        let (doc, p, self_id, _) = signed_fixture();
        // A relay tries to deliver to a different recipient.
        assert_eq!(
            verify_auth_deliver(
                &p,
                &doc,
                &[0x99; 32],
                NOW,
                DEFAULT_AUTH_DELIVER_FRESHNESS_SECS
            ),
            Err(AuthDeliverError::WrongRecipient),
        );
        // Sender claims an id that doesn't match the resolved doc.
        let mut wrong = doc.clone();
        wrong.node_id = [0x77; 32];
        assert_eq!(
            verify_auth_deliver(
                &p,
                &wrong,
                &self_id,
                NOW,
                DEFAULT_AUTH_DELIVER_FRESHNESS_SECS
            ),
            Err(AuthDeliverError::SenderMismatch),
        );
    }

    #[test]
    fn verify_rejects_stale_and_future() {
        let (doc, p, self_id, _) = signed_fixture();
        assert!(matches!(
            verify_auth_deliver(&p, &doc, &self_id, NOW + 10_000, 300),
            Err(AuthDeliverError::Stale { .. }),
        ));
        assert!(matches!(
            verify_auth_deliver(&p, &doc, &self_id, NOW - 10_000, 300),
            Err(AuthDeliverError::Stale { .. }),
        ));
    }

    #[test]
    fn verify_rejects_bad_key_index_and_expired_subkey() {
        let (doc, mut p, self_id, _) = signed_fixture();
        p.sig_key_idx = 5; // out of range (note: this also breaks the sig, but idx is checked first)
        assert_eq!(
            verify_auth_deliver(&p, &doc, &self_id, NOW, 300),
            Err(AuthDeliverError::BadKeyIndex(5)),
        );

        // Expired subkey window.
        let (mut doc2, p2, self_id2, _) = signed_fixture();
        doc2.identity_keys[0].valid_until_unix = NOW - 1;
        assert_eq!(
            verify_auth_deliver(&p2, &doc2, &self_id2, NOW, 300),
            Err(AuthDeliverError::SubkeyNotValid),
        );
    }
}
