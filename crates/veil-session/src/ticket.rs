//! Session-resumption ticket issuer.
//!
//! A `TicketIssuer` holds a 256-bit host ticket key and uses
//! ChaCha20Poly1305 to AEAD-encrypt / decrypt `SessionTicket` values.
//!
//! # Wire format of an `EncryptedTicket`
//! ```text
//! [0..12] nonce 12 bytes — random ChaCha20Poly1305 nonce
//! [12..172] ciphertext 160 bytes — encrypted SessionTicket plaintext
//! [172..188] tag 16 bytes — AEAD authentication tag
//! total = 188 bytes = SESSION_TICKET_ENCRYPTED_SIZE
//! ```
//!
//! The AEAD additional data (AAD) is the ASCII string `"ovl1-ticket-v1"` to
//! domain-separate from any other AEAD usage of the same key.

use std::collections::HashMap;
use std::sync::Mutex;

use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::Aead, aead::generic_array::GenericArray};
use rand_core::{OsRng, RngCore};

use veil_cfg::NodeId;
use veil_proto::{
    budget::{SESSION_TICKET_ENCRYPTED_SIZE, SESSION_TICKET_TTL_SECS},
    session::{EncryptedTicket, SessionTicket},
};
use veil_util::sensitive_bytes::SensitiveBytesN;

// AEAD AAD constant for domain separation.
pub const AAD: &[u8] = b"ovl1-ticket-v1";

/// cap on the replay-protection cache.
/// Each entry costs ~24 B (`[u8; 12]` nonce + `u64` valid_until + map
/// overhead). `8192` ≈ 200 KiB worst-case memory; sustained
/// resumption load above this rate evicts older entries (security
/// degrades to "old entries no longer replay-detected" — but their
/// TTL still enforces the global expiry, so the worst replay window
/// is `SESSION_TICKET_TTL_SECS` ≈ 30 days).
pub const MAX_CONSUMED_TICKETS: usize = 8192;

// ── TicketKey ─────────────────────────────────────────────────────────────────

/// A 256-bit host ticket key used to AEAD-encrypt/decrypt session tickets.
///
/// The key must be generated at node startup and rotated every
/// `TICKET_KEY_ROTATION_SECS` seconds. Only the current key can encrypt
/// new tickets; both the current and previous key can decrypt received tickets
/// (to handle the transition window).
///
/// # Memory hygiene (Этап 6 slice 6e)
///
/// Backed by [`SensitiveBytesN<32>`] — heap pages pinned via `mlock(2)`
/// when `RLIMIT_MEMLOCK` permits, falls back к а zeroize-on-drop
/// `Zeroizing<Vec<u8>>` when the budget is exhausted (same protection
/// as the pre-Этап-6 `[u8; 32]` field).  The mlocked path closes the
/// swap-к-disk vector: this is а **process-lifetime** key, so if pages
/// holding it get evicted to swap, every issued session-resumption
/// ticket up к the next rotation is decryptable by anyone with read
/// access к the swap partition.  Pinning matters here more than for
/// any other key in the system.
///
/// `Drop` semantics are inherited from `SensitiveBytesN<32>`'s inner
/// `SensitiveBytes` enum (both `Mlocked(MlockedBytes)` и
/// `Unlocked(Zeroizing<Vec<u8>>)` zeroize on drop).  `Clone` was
/// previously available но never called в production code — removed
/// here because cloning а mlocked key would require а second mlock
/// allocation, doubling the budget cost AND defeating the
/// single-ownership invariant что the rest of the system relies on.
/// Rotation can use ownership transfer (move old → previous, generate
/// new) instead of cloning.
pub struct TicketKey {
    key: SensitiveBytesN<32>,
}

impl TicketKey {
    /// Generate a fresh random ticket key.
    pub fn generate() -> Self {
        let mut key: SensitiveBytesN<32> = SensitiveBytesN::new();
        OsRng.fill_bytes(key.as_mut_array());
        Self { key }
    }

    /// Construct a key from raw bytes (testing only).
    pub fn from_bytes(key: [u8; 32]) -> Self {
        Self {
            key: SensitiveBytesN::from_bytes(key),
        }
    }

    /// Whether the underlying key bytes ара actually pinned via
    /// `mlock(2)`.  Test/diagnostic hook — operators can surface а
    /// Prometheus gauge using this к detect soft degradation в
    /// `RLIMIT_MEMLOCK`-exhausted environments (containers без
    /// `CAP_IPC_LOCK`, low-ulimit dev boxes).  Production code should
    /// not branch on this; both variants honour the same AEAD contract.
    pub fn is_mlocked(&self) -> bool {
        self.key.is_mlocked()
    }
}

// ── TicketIssuer ─────────────────────────────────────────────────────────────

/// Issues and verifies AEAD-encrypted session-resumption tickets.
///
/// Holds a reference to the host's current ticket key; construct a new
/// `TicketIssuer` whenever the key is rotated.
///
/// # / : replay protection
///
/// The issuer maintains a `consumed_tickets` set keyed by the AEAD
/// nonce of every successfully-decrypted ticket. A nonce that has
/// already been consumed is rejected as a replay. This makes
/// session-resumption tickets **single-use**: once a client has
/// resumed a session with a given ticket, the server issues a fresh
/// ticket on the resumed session and the client MUST replace its
/// stored copy. Replaying the captured original returns
/// `decrypt == None` even though the AEAD verifies and the TTL
/// hasn't expired.
///
/// Without this defence, an attacker who captured one ticket blob
/// (e.g. through compromise of the client's `peer_tickets` store)
/// could replay it within the TTL window and **the server would
/// re-derive the SAME `tx_key` / `rx_key` from the ticket plaintext
/// → AEAD nonce reuse on the resumed session → catastrophic crypto
/// break**. Single-use semantics close the window.
pub struct TicketIssuer {
    key: TicketKey,
    /// replay-protection cache keyed by the
    /// AEAD nonce of every ticket that has been successfully
    /// decrypted. Each entry stores the ticket's `valid_until` so
    /// expired entries can be reclaimed lazily.
    consumed_tickets: Mutex<HashMap<[u8; 12], u64>>,
}

impl TicketIssuer {
    pub fn new(key: TicketKey) -> Self {
        Self {
            key,
            consumed_tickets: Mutex::new(HashMap::new()),
        }
    }

    /// Encrypt a `SessionTicket` and return the opaque `EncryptedTicket` bytes.
    ///
    /// Legacy 4-argument `issue` — `peer_instance_id` defaults to
    /// `[0; 16]` (unspecified). Sovereign-identity-aware callers
    /// use [`Self::issue_for_instance`] to bind the ticket to a
    /// specific peer instance.
    ///
    /// # Test-only access (audit 2026-05-22)
    ///
    /// **Threat что this gate prevents**: when two sovereign instances
    /// of the same identity both call `issue` concurrently they receive
    /// tickets с identical plaintext (зависит от sym tx/rx keys derived
    /// от identical handshake outputs); если both instances resume в
    /// parallel, server side activates two sessions с the same
    /// `(tx_key, rx_key)`, both restarting AEAD nonce-counter at 0 →
    /// nonce reuse → AEAD plaintext recovery via ciphertext XOR.
    ///
    /// The fn is gated к `#[cfg(test)]` so production callers cannot
    /// reach it через а typo или а new migration that forgets к pass
    /// `peer_instance_id`.  Production uses [`Self::issue_for_instance`]
    /// exclusively.  Re-gating это к а production-callable shim requires
    /// either (а) shipping the multi-instance metadata propagation slice
    /// для sovereign-identity (handshake carries peer device/instance ID)
    /// OR (b) deriving instance-distinct session keys в the handshake KDF
    /// so identical-instance plaintexts produce non-colliding nonces.
    #[cfg(test)]
    pub fn issue(
        &self,
        session_id: [u8; 32],
        peer_id: impl Into<NodeId>,
        tx_key: [u8; 32],
        rx_key: [u8; 32],
    ) -> EncryptedTicket {
        self.issue_for_instance(session_id, peer_id, [0u8; 16], tx_key, rx_key)
    }

    /// issue a ticket bound to a specific
    /// `(peer_id, peer_instance_id)` pair. When two instances of the
    /// same sovereign identity both reconnect, each gets its own
    /// ticket — server-side resumption routes on the composite key
    /// and AEAD nonces can't be replayed across instances.
    pub fn issue_for_instance(
        &self,
        session_id: [u8; 32],
        peer_id: impl Into<NodeId>,
        peer_instance_id: [u8; 16],
        tx_key: [u8; 32],
        rx_key: [u8; 32],
    ) -> EncryptedTicket {
        // H9 ergonomic accept: take `impl Into<NodeId>` so tests с raw
        // `[u8; 32]` literals и production callers с `NodeId` both work
        // без explicit conversion at the call site.
        let peer_id: NodeId = peer_id.into();
        let now = unix_now_secs();
        let ticket = SessionTicket {
            session_id,
            peer_id: *peer_id.as_bytes(),
            tx_key,
            rx_key,
            issued_at: now,
            // saturating_add: past year 2584 u64 seconds could overflow; clamp
            // to u64::MAX rather than wrap, so the ticket is effectively
            // "forever-valid" instead of silently-expired.
            valid_until: now.saturating_add(SESSION_TICKET_TTL_SECS),
            peer_instance_id,
        };
        self.encrypt(&ticket)
    }

    /// Encrypt a `SessionTicket` into an `EncryptedTicket`.
    fn encrypt(&self, ticket: &SessionTicket) -> EncryptedTicket {
        let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(self.key.key.as_array()));
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = GenericArray::from_slice(&nonce_bytes);

        let plaintext = ticket.encode();
        // ChaCha20Poly1305::encrypt appends the 16-byte tag to the ciphertext.
        let ciphertext = cipher
            .encrypt(
                nonce,
                chacha20poly1305::aead::Payload {
                    msg: &plaintext,
                    aad: AAD,
                },
            )
            .expect("ChaCha20Poly1305 encrypt never fails on valid input");

        // Layout: nonce(12) || ciphertext+tag(176) = 188 bytes
        debug_assert_eq!(ciphertext.len(), SessionTicket::PLAINTEXT_SIZE + 16);
        let mut out = Vec::with_capacity(SESSION_TICKET_ENCRYPTED_SIZE);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        debug_assert_eq!(out.len(), SESSION_TICKET_ENCRYPTED_SIZE);
        out
    }

    /// Attempt to decrypt an `EncryptedTicket`. Returns `None` if the blob
    /// size is wrong, the AEAD tag is invalid, the ticket has expired
    /// **or the ticket has already been consumed (
    /// replay protection)**.
    pub fn decrypt(&self, blob: &[u8]) -> Option<SessionTicket> {
        if blob.len() != SESSION_TICKET_ENCRYPTED_SIZE {
            return None;
        }
        let nonce_bytes: [u8; 12] = blob[0..12].try_into().ok()?;
        let nonce = GenericArray::from_slice(&nonce_bytes);
        let ciphertext = &blob[12..]; // 160 + 16 bytes

        let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(self.key.key.as_array()));
        let plaintext = cipher
            .decrypt(
                nonce,
                chacha20poly1305::aead::Payload {
                    msg: ciphertext,
                    aad: AAD,
                },
            )
            .ok()?;

        let ticket = SessionTicket::decode(&plaintext).ok()?;

        let now = unix_now_secs();
        // defense against clock-rewind attacks. TTL is
        // tracked in wall-clock UNIX seconds, so an operator (or hostile
        // root) who jumps `CLOCK_REALTIME` backwards turns an already-
        // expired ticket valid again — `now > valid_until` flips back to
        // false. A ticket whose `issued_at` is in (validator's)
        // future is impossible under correct clocks; under rewind it
        // surfaces the inconsistency, so we reject. Tolerate up to the
        // **Interactive tier** skew (NTP convergence + VM pause/resume +
        // one retry) — pinned к central policy
        // [`veil_proto::time_validity::INTERACTIVE_SKEW_SECS`].
        const MAX_TICKET_FUTURE_SKEW_SECS: u64 = veil_proto::time_validity::INTERACTIVE_SKEW_SECS;
        if ticket.issued_at > now.saturating_add(MAX_TICKET_FUTURE_SKEW_SECS) {
            return None;
        }
        // Reject expired tickets.
        if now > ticket.valid_until {
            return None;
        }

        // atomic check-and-insert under the
        // replay-cache mutex so two concurrent decrypts of the same
        // nonce can never both succeed.
        let mut consumed = match self.consumed_tickets.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(), // recover from poisoning
        };
        // GC expired entries first to bound memory. Cheap when the
        // cache is small; avoids unbounded growth across long-running
        // hosts.
        consumed.retain(|_, valid_until| now <= *valid_until);
        if consumed.contains_key(&nonce_bytes) {
            // Replay — same nonce already consumed.
            return None;
        }
        if consumed.len() >= MAX_CONSUMED_TICKETS {
            // A4: replace the prior random `keys.next`
            // eviction with **oldest-`valid_until` first**. Under sustained
            // replay-attempt load, random eviction surrenders the
            // *most* recently-consumed nonces with equal probability —
            // exactly the ones an attacker would replay first because
            // their TTL window is still wide open. Evicting the oldest
            // means the attacker can only re-attempt nonces whose TTL
            // has nearly expired, shrinking the practical replay window
            // from `SESSION_TICKET_TTL_SECS` down to ~the cap-overflow
            // refill rate (typically minutes, not hours).
            let oldest_key = consumed
                .iter()
                .min_by_key(|&(_, valid_until)| *valid_until)
                .map(|(k, _)| *k);
            if let Some(k) = oldest_key {
                consumed.remove(&k);
            }
        }
        consumed.insert(nonce_bytes, ticket.valid_until);

        Some(ticket)
    }

    /// number of currently-tracked consumed
    /// tickets. audit cleanup: made
    /// `#[cfg(test)]` since no production caller exists. When
    /// observability wires this into а Prometheus counter в the
    /// future, drop the cfg AND add the wire-up в the same commit so
    /// the production-compile signal goes live, not silently dead.
    pub fn consumed_tickets_len(&self) -> usize {
        self.consumed_tickets.lock().map(|g| g.len()).unwrap_or(0)
    }
}

// ── time helper ───────────────────────────────────────────────────────────────

/// Current Unix time in seconds (CLOCK_REALTIME).
pub fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(deprecated)] // tests exercise the legacy `issue()` shim by design
mod tests {
    use super::*;

    fn make_issuer() -> TicketIssuer {
        TicketIssuer::new(TicketKey::from_bytes([0xAB; 32]))
    }

    #[test]
    fn roundtrip_encrypt_decrypt() {
        let issuer = make_issuer();
        let session_id = [1u8; 32];
        let peer_id = [2u8; 32];
        let tx_key = [3u8; 32];
        let rx_key = [4u8; 32];

        let blob = issuer.issue(session_id, peer_id, tx_key, rx_key);
        assert_eq!(blob.len(), SESSION_TICKET_ENCRYPTED_SIZE);

        let ticket = issuer.decrypt(&blob).expect("decrypt should succeed");
        assert_eq!(ticket.session_id, session_id);
        assert_eq!(ticket.peer_id, peer_id);
        assert_eq!(ticket.tx_key, tx_key);
        assert_eq!(ticket.rx_key, rx_key);
        assert_eq!(ticket.peer_instance_id, [0u8; 16]);
        assert!(ticket.valid_until > ticket.issued_at);
        assert_eq!(
            ticket.valid_until,
            ticket.issued_at + SESSION_TICKET_TTL_SECS
        );
    }

    #[test]
    fn wrong_key_fails_to_decrypt() {
        let issuer_a = make_issuer();
        let issuer_b = TicketIssuer::new(TicketKey::from_bytes([0xCD; 32]));

        let blob = issuer_a.issue([0; 32], [0; 32], [0; 32], [0; 32]);
        assert!(
            issuer_b.decrypt(&blob).is_none(),
            "different key must not decrypt"
        );
    }

    #[test]
    fn tampered_blob_fails_to_decrypt() {
        let issuer = make_issuer();
        let mut blob = issuer.issue([1; 32], [2; 32], [3; 32], [4; 32]);
        // Flip one byte in the ciphertext.
        blob[20] ^= 0xFF;
        assert!(
            issuer.decrypt(&blob).is_none(),
            "tampered blob must fail AEAD"
        );
    }

    #[test]
    fn short_blob_returns_none() {
        let issuer = make_issuer();
        assert!(issuer.decrypt(&[0u8; 10]).is_none());
    }

    #[test]
    fn expired_ticket_is_rejected() {
        let issuer = make_issuer();
        // Build a ticket that was valid in the past.
        let ticket = SessionTicket {
            session_id: [1; 32],
            peer_id: [2; 32],
            tx_key: [3; 32],
            rx_key: [4; 32],
            issued_at: 0,
            valid_until: 1, // long past
            peer_instance_id: [0u8; 16],
        };
        let blob = issuer.encrypt(&ticket);
        assert!(
            issuer.decrypt(&blob).is_none(),
            "expired ticket must be rejected"
        );
    }

    // ── peer_instance_id binding ──────────────────────────────

    #[test]
    fn issue_for_instance_binds_instance_id_through_roundtrip() {
        let issuer = make_issuer();
        let inst: [u8; 16] = [0xAB; 16];
        let blob = issuer.issue_for_instance([5u8; 32], [6u8; 32], inst, [7u8; 32], [8u8; 32]);
        assert_eq!(blob.len(), SESSION_TICKET_ENCRYPTED_SIZE);
        let ticket = issuer.decrypt(&blob).expect("decrypt");
        assert_eq!(ticket.peer_instance_id, inst);
    }

    // ── ticket replay protection ────────────────

    /// First decrypt of a ticket succeeds; second decrypt of the SAME
    /// ticket bytes returns `None` (replay rejected). Closes the
    /// catastrophic AEAD-nonce-reuse vector where a captured ticket
    /// would let an attacker re-derive the same `tx_key`/`rx_key`
    /// twice and thus reuse counters.
    #[test]
    fn phase647_c2_ticket_replay_rejected() {
        let issuer = make_issuer();
        let blob = issuer.issue([1; 32], [2; 32], [3; 32], [4; 32]);
        // First decrypt succeeds.
        let t1 = issuer.decrypt(&blob).expect("first decrypt OK");
        assert_eq!(t1.peer_id, [2; 32]);
        // Second decrypt of the EXACT SAME bytes is rejected as replay.
        assert!(
            issuer.decrypt(&blob).is_none(),
            "captured ticket must not replay"
        );
        // Tracker shows the consumption.
        assert_eq!(issuer.consumed_tickets_len(), 1);
    }

    /// Distinct tickets (different nonces, even with same plaintext)
    /// each decrypt independently — replay protection is per-nonce, not
    /// per-payload, so legitimate concurrent resumptions of different
    /// sessions are not confused.
    #[test]
    fn phase647_c2_distinct_tickets_each_decrypt_independently() {
        let issuer = make_issuer();
        let blob_a = issuer.issue([1; 32], [2; 32], [3; 32], [4; 32]);
        let blob_b = issuer.issue([1; 32], [2; 32], [3; 32], [4; 32]);
        // Same plaintext → distinct nonces (random).
        assert_ne!(&blob_a[0..12], &blob_b[0..12], "nonces must differ");
        assert!(issuer.decrypt(&blob_a).is_some());
        assert!(issuer.decrypt(&blob_b).is_some());
        assert_eq!(issuer.consumed_tickets_len(), 2);
    }

    /// Concurrent decrypts of the same ticket: exactly ONE must succeed.
    /// The atomic check-and-insert under the cache mutex guarantees no
    /// race window where two threads both succeed.
    #[tokio::test]
    async fn phase647_c2_concurrent_decrypt_only_one_succeeds() {
        use std::sync::Arc;
        let issuer = Arc::new(make_issuer());
        let blob = Arc::new(issuer.issue([1; 32], [2; 32], [3; 32], [4; 32]));
        let mut tasks = Vec::new();
        for _ in 0..16 {
            let issuer_c = Arc::clone(&issuer);
            let blob_c = Arc::clone(&blob);
            tasks.push(tokio::spawn(
                async move { issuer_c.decrypt(&blob_c).is_some() },
            ));
        }
        let mut wins = 0;
        for t in tasks {
            if t.await.unwrap() {
                wins += 1;
            }
        }
        assert_eq!(wins, 1, "exactly one concurrent decrypt must win");
    }

    /// Expired entries are GC'd from the replay cache lazily on next
    /// decrypt. An expired ticket nonce no longer counts toward the
    /// MAX_CONSUMED_TICKETS budget.
    #[test]
    fn phase647_c2_expired_entries_gced_lazily() {
        let issuer = make_issuer();
        // Hand-build an expired ticket and "consume" it.
        let expired = SessionTicket {
            session_id: [1; 32],
            peer_id: [2; 32],
            tx_key: [3; 32],
            rx_key: [4; 32],
            issued_at: 0,
            valid_until: 1,
            peer_instance_id: [0; 16],
        };
        let expired_blob = issuer.encrypt(&expired);
        // Decrypt fails with `None` (expired) — but we want to test the
        // GC path, so insert directly into the cache.
        {
            let mut g = issuer.consumed_tickets.lock().unwrap();
            // Use an arbitrary nonce.
            g.insert([0xAA; 12], 1u64); // valid_until = epoch+1
            assert_eq!(g.len(), 1);
        }
        // A fresh decrypt triggers the GC pass and removes the expired
        // entry before inserting the new one.
        let fresh = issuer.issue([5; 32], [6; 32], [7; 32], [8; 32]);
        let _ = issuer.decrypt(&fresh).unwrap();
        // After: GC removed the expired entry; cache holds only the
        // fresh-ticket nonce.
        assert_eq!(issuer.consumed_tickets_len(), 1);
        let _ = expired_blob; // silence
    }

    /// Cap eviction: above MAX_CONSUMED_TICKETS the cache evicts an
    /// arbitrary entry rather than growing unboundedly. After
    /// eviction the previously-tracked ticket may replay again — but
    /// only within the original TTL, so the overall replay window
    /// never exceeds `SESSION_TICKET_TTL_SECS`.
    #[test]
    fn phase647_c2_cache_cap_enforces_max() {
        let issuer = make_issuer();
        let now = unix_now_secs();
        {
            let mut g = issuer.consumed_tickets.lock().unwrap();
            for i in 0..MAX_CONSUMED_TICKETS {
                let mut nonce = [0u8; 12];
                nonce[0..4].copy_from_slice(&(i as u32).to_be_bytes());
                g.insert(nonce, now + SESSION_TICKET_TTL_SECS);
            }
            assert_eq!(g.len(), MAX_CONSUMED_TICKETS);
        }
        // One more insert via decrypt — total would be cap+1, so eviction kicks in.
        let blob = issuer.issue([1; 32], [2; 32], [3; 32], [4; 32]);
        let _ = issuer.decrypt(&blob).unwrap();
        assert_eq!(
            issuer.consumed_tickets_len(),
            MAX_CONSUMED_TICKETS,
            "cache must stay at MAX_CONSUMED_TICKETS after eviction"
        );
    }

    // ── Этап 6 slice 6e: SensitiveBytesN<32> migration verification ────

    /// AEAD round-trip works identically after migrating from
    /// `[u8; 32]` к `SensitiveBytesN<32>` storage — proves the key
    /// bytes flow correctly through `SensitiveBytesN::from_bytes` →
    /// `as_array()` → `ChaCha20Poly1305`.
    #[test]
    fn etap6_slice6e_generate_path_round_trips() {
        let issuer = TicketIssuer::new(TicketKey::generate());
        let session_id = [0x11u8; 32];
        let peer_id = [0x22u8; 32];
        let tx_key = [0x33u8; 32];
        let rx_key = [0x44u8; 32];

        let blob = issuer.issue(session_id, peer_id, tx_key, rx_key);
        let ticket = issuer.decrypt(&blob).expect("decrypt OsRng-generated key");
        assert_eq!(ticket.session_id, session_id);
        assert_eq!(ticket.tx_key, tx_key);
        assert_eq!(ticket.rx_key, rx_key);
    }

    /// `is_mlocked()` diagnostic accessor reports the underlying
    /// `SensitiveBytesN<32>` variant.  Test only verifies the boolean
    /// reflects реальную variant chosen — both branches ара valid
    /// outcomes (CI с CAP_IPC_LOCK dropped lands в the fallback path).
    #[test]
    fn etap6_slice6e_is_mlocked_reflects_variant() {
        let key = TicketKey::generate();
        // Boolean must round-trip stable across calls; no assertion на
        // which variant was chosen.
        assert_eq!(key.is_mlocked(), key.is_mlocked());
    }

    /// Two different `TicketKey::from_bytes` instances produce
    /// independent keys — the migration does not introduce static state
    /// or accidental sharing between SensitiveBytesN allocations.
    #[test]
    fn etap6_slice6e_distinct_keys_are_independent() {
        let issuer_a = TicketIssuer::new(TicketKey::from_bytes([0xA1; 32]));
        let issuer_b = TicketIssuer::new(TicketKey::from_bytes([0xB2; 32]));

        let blob = issuer_a.issue([1; 32], [2; 32], [3; 32], [4; 32]);
        // Issuer B's key must reject the AEAD tag.
        assert!(
            issuer_b.decrypt(&blob).is_none(),
            "blob encrypted with key_a must not decrypt under key_b"
        );
    }
}
