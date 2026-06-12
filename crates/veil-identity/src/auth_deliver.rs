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

/// Default reassembly timeout (seconds) for a partial authenticated message —
/// matches the freshness window: a message that can't reassemble within it
/// would fail freshness anyway.
pub const DEFAULT_AUTH_DELIVER_REASSEMBLY_TIMEOUT_SECS: u64 = DEFAULT_AUTH_DELIVER_FRESHNESS_SECS;
/// Default cap on concurrent in-flight (partial) reassemblies.
pub const DEFAULT_MAX_AUTH_DELIVER_REASSEMBLIES: usize = 256;
/// Default global cap on bytes buffered across all partial reassemblies.
pub const DEFAULT_MAX_AUTH_DELIVER_REASSEMBLY_BYTES: usize = 4 * 1024 * 1024;

/// Outcome of feeding one fragment to [`AuthDeliverReassembler::push`].
#[derive(Debug, PartialEq, Eq)]
pub enum ReassembleOutcome {
    /// Message still incomplete — more fragments needed.
    Pending,
    /// All fragments present — the reassembled `AuthAppDeliver` wire bytes.
    /// Verify them ONCE; the single signature integrity-protects the reassembly.
    Complete(Vec<u8>),
    /// Fragment dropped (bounds exceeded, inconsistent `frag_count`, or the
    /// per-message byte cap). The caller should count this for observability.
    Rejected,
}

struct Partial {
    frag_count: u16,
    received: Vec<Option<Vec<u8>>>,
    received_count: u16,
    bytes: usize,
    started_at: u64,
}

/// Bounded reassembler for fragmented authenticated rendezvous messages
/// ([`veil_proto::AuthDeliverFragment`]). Single-owner (the auth-deliver task),
/// so it carries no lock — feed fragments via [`Self::push`]; on the completing
/// fragment it returns the reassembled `AuthAppDeliver` bytes.
///
/// DoS bounds (the sender is onion-anonymous, so we cannot rate-limit per
/// sender): a global byte cap, a concurrent-message cap, a per-message byte cap
/// ([`veil_proto::MAX_AUTH_DELIVER_MSG_BYTES`]), and a timeout that GCs
/// partials. On concurrent-message pressure the LEAST-COMPLETE partial is
/// evicted (Δ2-g2), so a flood of fresh `msg_id`s cannot starve a nearly-done
/// legitimate reassembly.
pub struct AuthDeliverReassembler {
    messages: std::collections::HashMap<[u8; 16], Partial>,
    /// Insertion order (oldest at front) for timeout-GC + FIFO eviction.
    order: std::collections::VecDeque<[u8; 16]>,
    total_bytes: usize,
    max_messages: usize,
    max_total_bytes: usize,
    timeout_secs: u64,
}

impl AuthDeliverReassembler {
    /// Reassembler with default bounds.
    pub fn new() -> Self {
        Self::with_params(
            DEFAULT_MAX_AUTH_DELIVER_REASSEMBLIES,
            DEFAULT_MAX_AUTH_DELIVER_REASSEMBLY_BYTES,
            DEFAULT_AUTH_DELIVER_REASSEMBLY_TIMEOUT_SECS,
        )
    }

    /// Reassembler with explicit bounds.
    pub fn with_params(max_messages: usize, max_total_bytes: usize, timeout_secs: u64) -> Self {
        Self {
            messages: std::collections::HashMap::new(),
            order: std::collections::VecDeque::new(),
            total_bytes: 0,
            max_messages: max_messages.max(1),
            max_total_bytes,
            timeout_secs,
        }
    }

    /// Drop a partial by id, keeping `order` + `total_bytes` consistent.
    fn remove(&mut self, msg_id: &[u8; 16]) {
        if let Some(p) = self.messages.remove(msg_id) {
            self.total_bytes = self.total_bytes.saturating_sub(p.bytes);
            self.order.retain(|m| m != msg_id);
        }
    }

    /// Evict ONE partial under cap pressure, choosing the LEAST-COMPLETE one
    /// (fewest fragments received; ties broken by oldest, then id for
    /// determinism) — diff-audit Δ2-g2.
    ///
    /// FIFO-by-age (the previous behaviour) is the worst choice against a flood:
    /// an attacker spraying brand-new single-fragment `msg_id`s would evict the
    /// OLDEST partial, i.e. exactly the legitimate message closest to completing.
    /// Evicting the least-progressed partial instead means a near-complete real
    /// message survives a burst of fresh attacker partials. The sender is
    /// onion-anonymous so per-sender limiting is impossible; this is the
    /// available fairness lever.
    fn evict_one(&mut self) {
        let victim = self
            .messages
            .iter()
            .map(|(id, p)| (p.received_count, p.started_at, *id))
            .min();
        if let Some((_, _, id)) = victim {
            self.remove(&id);
        }
    }

    /// GC partials older than `timeout_secs` (FIFO → front is oldest).
    fn gc(&mut self, now_unix: u64) {
        while let Some(front) = self.order.front().copied() {
            match self.messages.get(&front) {
                Some(p) if now_unix.saturating_sub(p.started_at) >= self.timeout_secs => {
                    self.remove(&front);
                }
                Some(_) => break,
                None => {
                    self.order.pop_front();
                }
            }
        }
    }

    /// Feed one fragment. Returns [`ReassembleOutcome::Complete`] with the
    /// reassembled `AuthAppDeliver` bytes once every fragment has arrived.
    pub fn push(
        &mut self,
        frag: veil_proto::AuthDeliverFragment,
        now_unix: u64,
    ) -> ReassembleOutcome {
        self.gc(now_unix);
        let idx = frag.frag_idx as usize;
        let count = frag.frag_count;

        if self.messages.contains_key(&frag.msg_id) {
            // Validate against the existing partial under a short borrow, then
            // apply — avoids holding a `get_mut` borrow across `self.*` calls.
            let chunk_len = frag.chunk.len();
            let (consistent, duplicate, new_bytes, completes) = {
                let p = self.messages.get(&frag.msg_id).expect("present");
                if p.frag_count != count || idx >= p.received.len() {
                    (false, false, 0usize, false)
                } else if p.received[idx].is_some() {
                    (true, true, 0usize, false)
                } else {
                    let nb = p.bytes.saturating_add(chunk_len);
                    (true, false, nb, p.received_count + 1 == p.frag_count)
                }
            };
            if !consistent || new_bytes > veil_proto::MAX_AUTH_DELIVER_MSG_BYTES {
                let id = frag.msg_id;
                self.remove(&id);
                return ReassembleOutcome::Rejected;
            }
            if duplicate {
                return ReassembleOutcome::Pending;
            }
            {
                let p = self.messages.get_mut(&frag.msg_id).expect("present");
                p.bytes = new_bytes;
                p.received_count += 1;
                p.received[idx] = Some(frag.chunk);
            }
            self.total_bytes = self.total_bytes.saturating_add(chunk_len);
            if completes {
                let p = self.messages.remove(&frag.msg_id).expect("present");
                self.order.retain(|m| m != &frag.msg_id);
                self.total_bytes = self.total_bytes.saturating_sub(p.bytes);
                let mut out = Vec::with_capacity(p.bytes);
                for chunk in p.received {
                    out.extend_from_slice(&chunk.expect("all present at completion"));
                }
                return ReassembleOutcome::Complete(out);
            }
            self.enforce_total_bytes(&frag.msg_id);
            return ReassembleOutcome::Pending;
        }

        // New message.
        if count == 0
            || count > veil_proto::MAX_AUTH_DELIVER_FRAGMENTS
            || idx >= count as usize
            || frag.chunk.len() > veil_proto::MAX_AUTH_DELIVER_MSG_BYTES
        {
            return ReassembleOutcome::Rejected;
        }
        // Single-fragment fast path — complete immediately, no state.
        if count == 1 {
            return ReassembleOutcome::Complete(frag.chunk);
        }
        // Concurrent-message cap — evict the least-complete partial to make room
        // (Δ2-g2: protects nearly-done legit messages from a fresh-msg_id flood).
        while self.messages.len() >= self.max_messages {
            self.evict_one();
        }
        let chunk_len = frag.chunk.len();
        let mut received = vec![None; count as usize];
        received[idx] = Some(frag.chunk);
        self.messages.insert(
            frag.msg_id,
            Partial {
                frag_count: count,
                received,
                received_count: 1,
                bytes: chunk_len,
                started_at: now_unix,
            },
        );
        self.order.push_back(frag.msg_id);
        self.total_bytes = self.total_bytes.saturating_add(chunk_len);
        self.enforce_total_bytes(&frag.msg_id);
        ReassembleOutcome::Pending
    }

    /// Evict partials until under the global byte cap, never evicting `keep`
    /// (the message we just touched). Δ2-g2: targets the LEAST-complete partial
    /// (excluding `keep`), consistent with the concurrent-message cap, so a
    /// byte-flood of fresh msg_ids can't starve a nearly-done legit message.
    fn enforce_total_bytes(&mut self, keep: &[u8; 16]) {
        while self.total_bytes > self.max_total_bytes {
            let victim = self
                .messages
                .iter()
                .filter(|(id, _)| *id != keep)
                .map(|(id, p)| (p.received_count, p.started_at, *id))
                .min();
            match victim {
                Some((_, _, id)) => self.remove(&id),
                None => break, // only `keep` remains
            }
        }
    }
}

impl Default for AuthDeliverReassembler {
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
    // Recipient binding: `dst_node_id` is not on the wire — reconstruct it as
    // OUR node_id. A message actually signed for a DIFFERENT recipient yields
    // different signing bytes here → BadSignature (this replaces the old
    // explicit WrongRecipient check, now enforced cryptographically).
    verify_message(
        algo,
        &pk_b64,
        &p.signing_bytes_with_dst(self_node_id),
        &p.signature,
    )
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
            reply_block: None,
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
        // A relay tries to deliver to a different recipient. `dst_node_id` is
        // not on the wire — the wrong recipient reconstructs its own node_id as
        // dst, computes different signing bytes, and the signature fails.
        assert_eq!(
            verify_auth_deliver(
                &p,
                &doc,
                &[0x99; 32],
                NOW,
                DEFAULT_AUTH_DELIVER_FRESHNESS_SECS
            ),
            Err(AuthDeliverError::BadSignature),
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

    // ── reassembler ──────────────────────────────────────────────────────

    use veil_proto::AuthDeliverFragment;

    /// Split `bytes` into `n` fragments under one msg_id (ceil chunking).
    fn fragments_of(msg_id: [u8; 16], bytes: &[u8], n: u16) -> Vec<AuthDeliverFragment> {
        let chunk = bytes.len().div_ceil(n as usize).max(1);
        (0..n)
            .map(|i| AuthDeliverFragment {
                msg_id,
                frag_count: n,
                frag_idx: i,
                chunk: bytes
                    .chunks(chunk)
                    .nth(i as usize)
                    .map(|c| c.to_vec())
                    .unwrap_or_default(),
            })
            .collect()
    }

    #[test]
    fn reassembler_single_fragment_completes_immediately() {
        let mut r = AuthDeliverReassembler::new();
        let f = AuthDeliverFragment {
            msg_id: [1; 16],
            frag_count: 1,
            frag_idx: 0,
            chunk: b"whole signed AuthAppDeliver".to_vec(),
        };
        assert_eq!(
            r.push(f, NOW),
            ReassembleOutcome::Complete(b"whole signed AuthAppDeliver".to_vec()),
        );
    }

    #[test]
    fn reassembler_multi_fragment_reassembles_out_of_order() {
        let mut r = AuthDeliverReassembler::new();
        let original: Vec<u8> = (0..200u32).map(|i| i as u8).collect();
        let mut frags = fragments_of([7; 16], &original, 4);
        // Deliver in reverse order; only the last completes.
        frags.reverse();
        let last = frags.pop().unwrap();
        for f in frags {
            assert_eq!(r.push(f, NOW), ReassembleOutcome::Pending);
        }
        assert_eq!(r.push(last, NOW), ReassembleOutcome::Complete(original));
    }

    #[test]
    fn reassembler_ignores_duplicates_and_rejects_inconsistent_count() {
        let mut r = AuthDeliverReassembler::new();
        let frags = fragments_of([9; 16], &[0u8; 100], 3);
        assert_eq!(r.push(frags[0].clone(), NOW), ReassembleOutcome::Pending);
        // Duplicate idx 0 → ignored (still pending, no double count).
        assert_eq!(r.push(frags[0].clone(), NOW), ReassembleOutcome::Pending);
        // A fragment claiming a different frag_count for the same msg_id → reject.
        let mut bad = frags[1].clone();
        bad.frag_count = 5;
        assert_eq!(r.push(bad, NOW), ReassembleOutcome::Rejected);
    }

    #[test]
    fn reassembler_times_out_partials() {
        let mut r = AuthDeliverReassembler::with_params(64, 1 << 20, 300);
        let frags = fragments_of([3; 16], &[0u8; 100], 2);
        assert_eq!(r.push(frags[0].clone(), NOW), ReassembleOutcome::Pending);
        // The other fragment arrives after the timeout → the partial was GC'd, so
        // this is treated as a fresh (still-incomplete) message, not a completion.
        assert_eq!(
            r.push(frags[1].clone(), NOW + 301),
            ReassembleOutcome::Pending
        );
    }

    #[test]
    fn reassembler_concurrent_cap_evicts_under_pressure() {
        let mut r = AuthDeliverReassembler::with_params(2, 1 << 20, 300);
        // 3 distinct in-flight 2-fragment messages, all equally (1/2) complete;
        // cap is 2 → one is evicted. With equal completeness the tie-break is
        // (started_at, msg_id), so the smallest id ([0;16]) goes.
        for id in 0u8..3 {
            let f = fragments_of([id; 16], &[0u8; 50], 2);
            assert_eq!(r.push(f[0].clone(), NOW), ReassembleOutcome::Pending);
        }
        let f0 = fragments_of([0; 16], &[0u8; 50], 2);
        assert_eq!(r.push(f0[1].clone(), NOW), ReassembleOutcome::Pending);
    }

    #[test]
    fn reassembler_evicts_least_complete_not_oldest_g2() {
        // diff-audit Δ2-g2: under a flood of fresh msg_ids, a nearly-complete
        // legit message must survive — eviction targets the LEAST-complete
        // partial, not the oldest.
        let mut r = AuthDeliverReassembler::with_params(2, 1 << 20, 600);
        let a = fragments_of([0xAA; 16], &[1u8; 90], 3); // 3 fragments
        let b = fragments_of([0xBB; 16], &[2u8; 90], 3);
        let c = fragments_of([0xCC; 16], &[3u8; 90], 3);
        // A (oldest) advances to 2/3; B is newer at 1/3. messages = {A, B}.
        assert_eq!(r.push(a[0].clone(), NOW), ReassembleOutcome::Pending);
        assert_eq!(r.push(a[1].clone(), NOW), ReassembleOutcome::Pending);
        assert_eq!(r.push(b[0].clone(), NOW), ReassembleOutcome::Pending);
        // A fresh msg_id forces an eviction: B (least complete) goes, A survives.
        assert_eq!(r.push(c[0].clone(), NOW), ReassembleOutcome::Pending);
        // A's final fragment COMPLETES it (proves A was not evicted). Under the
        // old FIFO-by-age rule, A (oldest) would have been evicted → Pending.
        assert!(matches!(
            r.push(a[2].clone(), NOW),
            ReassembleOutcome::Complete(_)
        ));
        // B (evicted) no longer completes from its remaining fragments alone.
        assert_eq!(r.push(b[1].clone(), NOW), ReassembleOutcome::Pending);
    }
}
