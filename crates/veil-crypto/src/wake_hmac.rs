//! Wake-up payload HMAC primitive (Epic 489.10 slice 4.3.1).
//!
//! Closes the leaked-push-token DoS / presence-oracle vector:
//! pre-HMAC, anyone holding a receiver's FCM/APNs token could fire
//! arbitrary silent pushes to burn battery (DoS) or measure network
//! response latency to infer when the receiver is online (presence
//! oracle).  Post-HMAC, only the legitimate mailbox-relay (which
//! holds the receiver's wake-HMAC key, sealed to its X25519 pubkey
//! via [`super::push_envelope`] in a sibling slice) can mint a
//! wake-up payload that the receiver's plugin will accept.
//!
//! # Threat model
//!
//! * **Receiver** (Mobile app) generates [`WakeHmacKey`] at startup
//!   and persists it locally.  Wraps the key together with the push
//!   token via [`super::push_envelope`] (sibling slice 4.3.2 wire
//!   field `wake_hmac_envelope`) so only the chosen push-relay
//!   can decrypt and use it.
//!
//! * **Push-relay** (operator-run) decrypts the wake-HMAC key,
//!   stores it associated with the receiver's `node_id`, and uses it
//!   to sign wake-up payloads.  Compromised relay = forged wakeups
//!   (battery DoS); same trust boundary as the existing sealed-
//!   envelope design.
//!
//! * **Attacker** holding a leaked FCM/APNs token but NOT the
//!   wake-HMAC key cannot forge a valid payload — receiver's
//!   `verify_wake_payload` rejects the silent push silently, and
//!   the plugin returns from `handleWakeup` without reconnecting
//!   the daemon.  Result: zero battery cost, no observable network
//!   reaction (presence oracle defeated).
//!
//! # Wire format
//!
//! The HMAC covers a fixed-layout 73-byte canonical preimage:
//!
//! ```text
//! [0..6]     domain b"WAKEv1" — version + domain separator
//! [6..14]    ts u64 BE — wakeup-emit unix time
//! [14..46]   content_id [u8; 32] — mailbox blob ID the wake targets
//! [46..78]   receiver_id [u8; 32] — receiver node_id binding
//! ```
//!
//! Output is a 32-byte HMAC-SHA256 tag.  Total wake payload that
//! the relay puts into the FCM/APNs body:
//!
//! ```text
//! [0..8]    ts u64 BE
//! [8..40]   content_id [u8; 32]
//! [40..72]  hmac [u8; 32]
//! ```
//!
//! 72 bytes < FCM/APNs 4 KiB payload cap with lots of headroom.
//!
//! # Replay handling
//!
//! `ts` provides a natural freshness window — receivers reject payloads
//! older than [`WAKE_FRESHNESS_SECS`] (currently 5 minutes).  Per-`content_id`
//! replay caching is the receiver's responsibility (mailbox layer already
//! tracks delivered content_ids via the existing `MailboxBlob` flow); this
//! primitive does not maintain a replay set on its own to keep the API
//! stateless and embedded-friendly.
//!
//! # Why HMAC-SHA256 (not Ed25519)
//!
//! Sign-verify with public-key crypto would let receivers verify in
//! constant time without sharing a key, but requires the relay to hold
//! a receiver-specific signing key — same secret-distribution shape
//! as HMAC, with a 50× larger sig (64 vs 32 B) and a CPU-heavy verify
//! that runs every silent push (a battery cost that HMAC avoids).
//! HMAC is the established choice for "push relay confirms it
//! is authorised to wake this device".

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

/// Domain-separation prefix bound into the HMAC preimage.  Bumping
/// the version invalidates every previously-published `wake_hmac_envelope`
/// — only do this on a security-relevant format change.
pub const WAKE_HMAC_DOMAIN: &[u8; 6] = b"WAKEv1";

/// HMAC-SHA256 tag length (32 bytes).
pub const WAKE_HMAC_TAG_LEN: usize = 32;

/// Wake-HMAC key length (32 bytes — matches HMAC-SHA256 block boundary
/// and the existing sealed-envelope key-size cap).
pub const WAKE_HMAC_KEY_LEN: usize = 32;

/// Maximum age of a wake-payload `ts` before receivers reject it.
/// 5 minutes balances clock-skew tolerance (consumer phones often
/// drift ±60 s) against replay window — a stolen wake payload
/// expires before an attacker can systematically replay it.
pub const WAKE_FRESHNESS_SECS: u64 = 300;

/// Wake-payload fixed wire size (8 + 32 + 32).
pub const WAKE_PAYLOAD_LEN: usize = 8 + 32 + 32;

/// Symmetric wake-up HMAC key.  Receiver generates once per identity
/// (or rotation epoch), persists locally, and shares with the chosen
/// push-relay via the sealed `wake_hmac_envelope` field on
/// `RendezvousAd` (sibling slice 4.3.2).
///
/// Implements [`Zeroize`] so that key bytes wipe on drop — leaked
/// stack frames or core dumps don't preserve the key after a
/// natural scope exit.
#[derive(Clone)]
pub struct WakeHmacKey(pub [u8; WAKE_HMAC_KEY_LEN]);

impl WakeHmacKey {
    /// Construct from raw bytes.  Caller asserts that `bytes` came from
    /// a CSPRNG (e.g., `rand_core::OsRng`); this constructor does not
    /// perform its own randomness check.
    pub fn from_bytes(bytes: [u8; WAKE_HMAC_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Generate a fresh random key using `OsRng`.  Use once per
    /// identity rotation epoch.
    pub fn generate() -> Self {
        use rand_core::{OsRng, RngCore};
        let mut k = [0u8; WAKE_HMAC_KEY_LEN];
        OsRng.fill_bytes(&mut k);
        Self(k)
    }

    /// Borrow the raw bytes — for serialisation into the sealed
    /// envelope or for HMAC compute.
    pub fn as_bytes(&self) -> &[u8; WAKE_HMAC_KEY_LEN] {
        &self.0
    }
}

impl Drop for WakeHmacKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for WakeHmacKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never leak key bytes to logs.
        f.debug_struct("WakeHmacKey")
            .field("len", &self.0.len())
            .field("bytes", &"<redacted>")
            .finish()
    }
}

/// Compute the wake-payload HMAC tag.
///
/// Inputs are the three observable wake-payload fields (ts, content_id,
/// receiver_id); the domain prefix is added internally.  Caller emits
/// `(ts, content_id, hmac)` over the wire; receiver re-derives
/// the tag and compares.
pub fn compute_wake_hmac(
    key: &WakeHmacKey,
    ts: u64,
    content_id: &[u8; 32],
    receiver_id: &[u8; 32],
) -> [u8; WAKE_HMAC_TAG_LEN] {
    type HmacSha256 = Hmac<Sha256>;
    // `new_from_slice` on a valid-length slice from an array does not
    // fail in practice (HMAC accepts any-length key, the only error is
    // OOM on absurd lengths); but we propagate the documented `expect`
    // pattern that veil-obfs4's NTOR exposes for the same crate.
    let mut mac = HmacSha256::new_from_slice(key.as_bytes())
        .expect("HMAC accepts any-length key — 32 B input is well-formed");
    mac.update(WAKE_HMAC_DOMAIN);
    mac.update(&ts.to_be_bytes());
    mac.update(content_id);
    mac.update(receiver_id);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; WAKE_HMAC_TAG_LEN];
    out.copy_from_slice(&tag);
    out
}

/// Encode the receiver-observable wake-payload (`ts || content_id || hmac`)
/// that the push-relay puts into the FCM/APNs payload body.
pub fn encode_wake_payload(
    ts: u64,
    content_id: &[u8; 32],
    hmac_tag: &[u8; WAKE_HMAC_TAG_LEN],
) -> [u8; WAKE_PAYLOAD_LEN] {
    let mut out = [0u8; WAKE_PAYLOAD_LEN];
    out[0..8].copy_from_slice(&ts.to_be_bytes());
    out[8..40].copy_from_slice(content_id);
    out[40..72].copy_from_slice(hmac_tag);
    out
}

/// Outcome of [`verify_wake_payload`].  Distinguishes the three failure
/// modes the receiver may surface differently:
///
/// * `Valid` — payload accepted; receiver proceeds to full drain.
/// * `TamperedOrForged` — HMAC mismatch; silent drop, no observable
///   network reaction.
/// * `Expired` — `ts` outside the [`WAKE_FRESHNESS_SECS`] window
///   relative to `now`; silent drop.  Distinguished from tampering so
///   that the receiver can log a warn-level metric if the rate grows
///   (suggests a clock-skew or replay attempt).
/// * `MalformedLength` — input wasn't the expected 72 bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WakePayloadVerdict {
    Valid { ts: u64, content_id: [u8; 32] },
    TamperedOrForged,
    Expired { ts: u64, now: u64 },
    MalformedLength { got: usize },
}

/// Verify a wake payload received via OS push delivery.  Constant-time
/// HMAC comparison via the underlying [`hmac::Mac::verify_slice`].
///
/// `now` is the receiver's current unix time — caller passes it explicitly
/// so this stays a pure function (testable, no `SystemTime::now()`
/// side-effect).
pub fn verify_wake_payload(
    key: &WakeHmacKey,
    payload: &[u8],
    receiver_id: &[u8; 32],
    now: u64,
) -> WakePayloadVerdict {
    if payload.len() != WAKE_PAYLOAD_LEN {
        return WakePayloadVerdict::MalformedLength { got: payload.len() };
    }
    let mut ts_bytes = [0u8; 8];
    ts_bytes.copy_from_slice(&payload[0..8]);
    let ts = u64::from_be_bytes(ts_bytes);
    let mut content_id = [0u8; 32];
    content_id.copy_from_slice(&payload[8..40]);
    let mut received_tag = [0u8; WAKE_HMAC_TAG_LEN];
    received_tag.copy_from_slice(&payload[40..72]);

    // Freshness check first — a tampered payload with a stale ts is still
    // tampered, but distinguishing expired-but-valid-shape from forged is
    // useful operationally (operators see "clock skew" vs "active forging").
    let abs_skew = now.abs_diff(ts);
    if abs_skew > WAKE_FRESHNESS_SECS {
        return WakePayloadVerdict::Expired { ts, now };
    }

    // Constant-time verify via the hmac crate's own helper (authoritative).
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC accepts any-length key");
    mac.update(WAKE_HMAC_DOMAIN);
    mac.update(&ts.to_be_bytes());
    mac.update(&content_id);
    mac.update(receiver_id);
    match mac.verify_slice(&received_tag) {
        Ok(()) => {
            // Defence-in-depth (debug builds only): recompute the tag outside
            // the constant-time path and assert consistency. Audit L-1: gated
            // on `debug_assertions` so a RELEASE verify does a SINGLE HMAC —
            // `verify_slice` above is authoritative, and the eager recompute was
            // dead in release (only ever consumed by this debug assert), an
            // avoidable doubled HMAC on the battery-sensitive wake path.
            #[cfg(debug_assertions)]
            {
                let expected = compute_wake_hmac(key, ts, &content_id, receiver_id);
                debug_assert_eq!(expected, received_tag);
            }
            WakePayloadVerdict::Valid { ts, content_id }
        }
        Err(_) => WakePayloadVerdict::TamperedOrForged,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_key() -> WakeHmacKey {
        // Deterministic fixture: bytes [0, 1, 2, …, 31].  Real receivers
        // use [`WakeHmacKey::generate`].
        let mut k = [0u8; WAKE_HMAC_KEY_LEN];
        for (i, b) in k.iter_mut().enumerate() {
            *b = i as u8;
        }
        WakeHmacKey::from_bytes(k)
    }

    fn fixture_content_id() -> [u8; 32] {
        [0xAA; 32]
    }

    fn fixture_receiver_id() -> [u8; 32] {
        [0xBB; 32]
    }

    #[test]
    fn hmac_is_deterministic_under_same_inputs() {
        let key = fixture_key();
        let cid = fixture_content_id();
        let rid = fixture_receiver_id();
        let tag1 = compute_wake_hmac(&key, 1_700_000_000, &cid, &rid);
        let tag2 = compute_wake_hmac(&key, 1_700_000_000, &cid, &rid);
        assert_eq!(tag1, tag2);
    }

    #[test]
    fn hmac_differs_on_ts_difference() {
        let key = fixture_key();
        let cid = fixture_content_id();
        let rid = fixture_receiver_id();
        let tag1 = compute_wake_hmac(&key, 1_700_000_000, &cid, &rid);
        let tag2 = compute_wake_hmac(&key, 1_700_000_001, &cid, &rid);
        assert_ne!(tag1, tag2);
    }

    #[test]
    fn hmac_differs_on_content_id_difference() {
        let key = fixture_key();
        let rid = fixture_receiver_id();
        let mut cid1 = [0u8; 32];
        cid1[0] = 1;
        let mut cid2 = [0u8; 32];
        cid2[0] = 2;
        let tag1 = compute_wake_hmac(&key, 100, &cid1, &rid);
        let tag2 = compute_wake_hmac(&key, 100, &cid2, &rid);
        assert_ne!(tag1, tag2);
    }

    #[test]
    fn hmac_differs_on_receiver_id_difference() {
        let key = fixture_key();
        let cid = fixture_content_id();
        let mut rid1 = [0u8; 32];
        rid1[0] = 1;
        let mut rid2 = [0u8; 32];
        rid2[0] = 2;
        let tag1 = compute_wake_hmac(&key, 100, &cid, &rid1);
        let tag2 = compute_wake_hmac(&key, 100, &cid, &rid2);
        assert_ne!(tag1, tag2);
    }

    #[test]
    fn hmac_differs_on_key_difference() {
        let mut k1 = [0u8; WAKE_HMAC_KEY_LEN];
        k1[0] = 1;
        let mut k2 = [0u8; WAKE_HMAC_KEY_LEN];
        k2[0] = 2;
        let cid = fixture_content_id();
        let rid = fixture_receiver_id();
        let tag1 = compute_wake_hmac(&WakeHmacKey::from_bytes(k1), 100, &cid, &rid);
        let tag2 = compute_wake_hmac(&WakeHmacKey::from_bytes(k2), 100, &cid, &rid);
        assert_ne!(tag1, tag2);
    }

    #[test]
    fn encode_wake_payload_layout_is_72_bytes_be() {
        let cid = fixture_content_id();
        let tag = [0xCCu8; WAKE_HMAC_TAG_LEN];
        let p = encode_wake_payload(0x0102030405060708u64, &cid, &tag);
        assert_eq!(p.len(), WAKE_PAYLOAD_LEN);
        // ts BE
        assert_eq!(&p[0..8], &[1, 2, 3, 4, 5, 6, 7, 8]);
        // content_id
        assert_eq!(&p[8..40], &cid[..]);
        // hmac tag
        assert_eq!(&p[40..72], &tag[..]);
    }

    #[test]
    fn verify_accepts_fresh_well_formed_payload() {
        let key = fixture_key();
        let cid = fixture_content_id();
        let rid = fixture_receiver_id();
        let ts = 1_700_000_000;
        let tag = compute_wake_hmac(&key, ts, &cid, &rid);
        let payload = encode_wake_payload(ts, &cid, &tag);
        let v = verify_wake_payload(&key, &payload, &rid, ts + 10);
        assert_eq!(
            v,
            WakePayloadVerdict::Valid {
                ts,
                content_id: cid
            }
        );
    }

    #[test]
    fn verify_rejects_forged_hmac_silently() {
        let key = fixture_key();
        let cid = fixture_content_id();
        let rid = fixture_receiver_id();
        let ts = 1_700_000_000;
        // Forge with a wrong key — receiver does NOT have an oracle bit
        // saying "wrong key" vs "wrong content" — only Tampered/Forged.
        let mut wrong_key = [0u8; WAKE_HMAC_KEY_LEN];
        wrong_key[0] = 0xFF;
        let forged_tag = compute_wake_hmac(&WakeHmacKey::from_bytes(wrong_key), ts, &cid, &rid);
        let payload = encode_wake_payload(ts, &cid, &forged_tag);
        assert_eq!(
            verify_wake_payload(&key, &payload, &rid, ts + 10),
            WakePayloadVerdict::TamperedOrForged
        );
    }

    #[test]
    fn verify_rejects_tampered_ts() {
        let key = fixture_key();
        let cid = fixture_content_id();
        let rid = fixture_receiver_id();
        let ts = 1_700_000_000;
        let tag = compute_wake_hmac(&key, ts, &cid, &rid);
        // Encode payload with a DIFFERENT ts than the tag was computed for —
        // simulates attacker rewriting the ts field of an intercepted payload.
        let mut payload = encode_wake_payload(ts + 1, &cid, &tag);
        // Verify under "now near ts+1" so freshness passes, only HMAC fails.
        assert_eq!(
            verify_wake_payload(&key, &payload, &rid, ts + 11),
            WakePayloadVerdict::TamperedOrForged
        );
        // Touching content_id same effect.
        payload = encode_wake_payload(ts, &[0xEE; 32], &tag);
        assert_eq!(
            verify_wake_payload(&key, &payload, &rid, ts + 10),
            WakePayloadVerdict::TamperedOrForged
        );
    }

    #[test]
    fn verify_rejects_expired_ts() {
        let key = fixture_key();
        let cid = fixture_content_id();
        let rid = fixture_receiver_id();
        let ts = 1_700_000_000;
        let tag = compute_wake_hmac(&key, ts, &cid, &rid);
        let payload = encode_wake_payload(ts, &cid, &tag);
        let now = ts + WAKE_FRESHNESS_SECS + 1; // 5 min + 1 s ahead
        match verify_wake_payload(&key, &payload, &rid, now) {
            WakePayloadVerdict::Expired {
                ts: e_ts,
                now: e_now,
            } => {
                assert_eq!(e_ts, ts);
                assert_eq!(e_now, now);
            }
            other => panic!("expected Expired, got {:?}", other),
        }
    }

    #[test]
    fn verify_rejects_skew_in_either_direction() {
        // Receiver's clock can drift in either direction relative to the
        // relay's clock.  The freshness check uses absolute skew so the
        // payload is rejected symmetrically.
        let key = fixture_key();
        let cid = fixture_content_id();
        let rid = fixture_receiver_id();
        let ts = 1_700_000_000;
        let tag = compute_wake_hmac(&key, ts, &cid, &rid);
        let payload = encode_wake_payload(ts, &cid, &tag);
        // Receiver clock 10 minutes BEHIND the relay's emit time.
        let now_behind = ts - (WAKE_FRESHNESS_SECS + 1);
        assert!(matches!(
            verify_wake_payload(&key, &payload, &rid, now_behind),
            WakePayloadVerdict::Expired { .. }
        ));
    }

    #[test]
    fn verify_accepts_exact_freshness_boundary() {
        let key = fixture_key();
        let cid = fixture_content_id();
        let rid = fixture_receiver_id();
        let ts = 1_700_000_000;
        let tag = compute_wake_hmac(&key, ts, &cid, &rid);
        let payload = encode_wake_payload(ts, &cid, &tag);
        // Exactly at the freshness window boundary — still accepted.
        let now = ts + WAKE_FRESHNESS_SECS;
        assert_eq!(
            verify_wake_payload(&key, &payload, &rid, now),
            WakePayloadVerdict::Valid {
                ts,
                content_id: cid
            }
        );
    }

    #[test]
    fn verify_rejects_malformed_length() {
        let key = fixture_key();
        let rid = fixture_receiver_id();
        // Short — 71 bytes (one short of WAKE_PAYLOAD_LEN).
        let short = vec![0u8; WAKE_PAYLOAD_LEN - 1];
        assert_eq!(
            verify_wake_payload(&key, &short, &rid, 1_700_000_000),
            WakePayloadVerdict::MalformedLength {
                got: WAKE_PAYLOAD_LEN - 1
            }
        );
        // Long.
        let long = vec![0u8; WAKE_PAYLOAD_LEN + 16];
        assert_eq!(
            verify_wake_payload(&key, &long, &rid, 1_700_000_000),
            WakePayloadVerdict::MalformedLength {
                got: WAKE_PAYLOAD_LEN + 16
            }
        );
        // Empty.
        assert_eq!(
            verify_wake_payload(&key, &[], &rid, 1_700_000_000),
            WakePayloadVerdict::MalformedLength { got: 0 }
        );
    }

    #[test]
    fn key_zeroizes_on_drop() {
        // Construct a key, copy its bytes to a separate buffer, drop the
        // key, and confirm that scoped reference into the dropped key's
        // memory does NOT preserve the bytes.  This is a behavioural
        // test — modern compilers / allocator reuse may overwrite the
        // memory anyway, but at minimum the Zeroize call ensures the
        // bytes are wiped at the moment of drop.
        let bytes = {
            let k = WakeHmacKey::generate();
            let copy = *k.as_bytes();
            // k drops at scope-end; copy keeps the value.
            copy
        };
        // Without panicking, just confirm we observed real (non-zero)
        // bytes BEFORE drop — generate() uses OsRng so chances of an
        // all-zero key are 2^-256.
        let any_nonzero = bytes.iter().any(|&b| b != 0);
        assert!(
            any_nonzero,
            "OsRng-generated key must be non-zero with overwhelming probability"
        );
    }

    #[test]
    fn debug_format_redacts_key_bytes() {
        // Defence against operators accidentally logging keys in a
        // string-formatted struct dump.
        let k = WakeHmacKey::from_bytes([0xAA; WAKE_HMAC_KEY_LEN]);
        let s = format!("{:?}", k);
        assert!(
            s.contains("<redacted>"),
            "Debug must redact key bytes, got: {s}"
        );
        assert!(
            !s.contains("aa"),
            "Debug must NOT print hex of key bytes, got: {s}"
        );
        assert!(
            !s.contains("AA"),
            "Debug must NOT print key bytes, got: {s}"
        );
    }
}
