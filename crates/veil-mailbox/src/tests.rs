//! Integration tests [`crate::Mailbox`].

use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

fn fresh(cfg: MailboxConfig) -> (Mailbox, tempfile::TempDir, Arc<AtomicU64>) {
    let tmp = tempfile::tempdir().unwrap();
    let clock = Arc::new(AtomicU64::new(1_700_000_000)); //  ish
    let clk = Arc::clone(&clock);
    let mb = Mailbox::open_with_clock(tmp.path(), cfg, move || clk.load(Ordering::SeqCst)).unwrap();
    (mb, tmp, clock)
}

#[test]
fn t1_4_p1_put_then_fetch_round_trip() {
    let (mb, _tmp, _clk) = fresh(MailboxConfig::default());
    let recv = [11u8; 32];
    let cid = [22u8; 32];
    let sender = [33u8; 32];
    let payload = b"opaque-encrypted-blob".to_vec();

    let outcome = mb.put(recv, cid, sender, payload.clone()).unwrap();
    assert!(matches!(outcome, PutOutcome::Stored { evicted: 0 }));

    let mut got = mb.fetch(recv).unwrap();
    assert_eq!(got.len(), 1);
    let blob = got.pop().unwrap();
    assert_eq!(blob.sender_id, sender);
    assert_eq!(blob.content_id, cid);
    assert_eq!(blob.blob, payload);
}

#[test]
fn t1_4_p1_duplicate_put_is_noop() {
    let (mb, _tmp, _clk) = fresh(MailboxConfig::default());
    let recv = [1u8; 32];
    let cid = [2u8; 32];
    let sender = [3u8; 32];

    assert!(matches!(
        mb.put(recv, cid, sender, b"first".to_vec()).unwrap(),
        PutOutcome::Stored { evicted: 0 },
    ));
    // Same (recv, cid) → Duplicate, original preserved.
    assert_eq!(
        mb.put(recv, cid, sender, b"OVERWRITE-ATTEMPT".to_vec())
            .unwrap(),
        PutOutcome::Duplicate,
    );
    let got = mb.fetch(recv).unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].blob, b"first");
}

#[test]
fn t1_4_p1_per_receiver_quota_rejects_when_exceeded() {
    // Room for exactly one 80-byte record.
    //
    // Quotas are charged in BILLABLE bytes — the payload plus the overhead a
    // stored row actually costs (audit V-05) — so the cap is expressed the
    // same way. Charging payload alone let a byte quota admit millions of
    // one-byte records and run the relay out of disk long before it ran out
    // of quota.
    let cfg = MailboxConfig {
        quota_per_receiver_bytes: crate::billable_bytes(80),
        rate_limit_per_minute: 0, // disable to focus on quota
        ..MailboxConfig::default()
    };
    let (mb, _tmp, _clk) = fresh(cfg);
    let recv = [1u8; 32];

    // Exactly fills the cap.
    let out = mb.put(recv, [1u8; 32], [9u8; 32], vec![0u8; 80]).unwrap();
    assert!(matches!(out, PutOutcome::Stored { .. }));

    // Nothing else fits, however small — which is the point: a 30-byte
    // payload is not a 30-byte record.
    let out = mb.put(recv, [2u8; 32], [9u8; 32], vec![0u8; 30]).unwrap();
    match out {
        PutOutcome::QuotaPerReceiverExceeded {
            current_bytes,
            cap_bytes,
        } => {
            assert_eq!(current_bytes, crate::billable_bytes(80));
            assert_eq!(cap_bytes, crate::billable_bytes(80));
        }
        other => panic!("expected QuotaPerReceiverExceeded, got {:?}", other),
    }

    // Different receiver — independent. Allowed.
    let other_recv = [2u8; 32];
    let out = mb
        .put(other_recv, [3u8; 32], [9u8; 32], vec![0u8; 80])
        .unwrap();
    assert!(matches!(out, PutOutcome::Stored { .. }));
}

#[test]
fn t1_4_p1_global_quota_evicts_oldest_first() {
    // Global cap: room for exactly TWO 80-byte records, so the third has to
    // evict one. Sized in billable bytes — payload plus per-record overhead
    // (audit V-05) — because that is what the quota now charges.
    let cfg = MailboxConfig {
        quota_per_receiver_bytes: u64::MAX,
        quota_global_bytes: 2 * crate::billable_bytes(80),
        rate_limit_per_minute: 0,
        require_capability_token: false,
        quota_per_sender_bytes: u64::MAX,
        local_node_id: [0u8; 32],
        ..MailboxConfig::default()
    };
    let (mb, _tmp, clk) = fresh(cfg);
    let r1 = [1u8; 32];
    let r2 = [2u8; 32];

    // audit: eviction protects blobs younger than
    // MIN_EVICTION_AGE_SECS (3600 s). Time gaps below need to exceed
    // this threshold for legitimate eviction to happen — otherwise the
    // put is rejected with QuotaGlobalExceeded.
    // t=0: r1 puts 80 bytes (id=A).
    clk.store(0, Ordering::SeqCst);
    mb.put(r1, [b'A'; 32], [9u8; 32], vec![0u8; 80]).unwrap();
    // t=10000: r2 puts 80 bytes (id=B). Total = 160 < 200.
    clk.store(10_000, Ordering::SeqCst);
    mb.put(r2, [b'B'; 32], [9u8; 32], vec![0u8; 80]).unwrap();
    // t=20000: r1 puts 80 bytes (id=C). Total would be 240 > 200.
    // A is now ~20000 s old (>> MIN_EVICTION_AGE_SECS) so eligible
    // for eviction — the oldest globally is A from r1.
    clk.store(20_000, Ordering::SeqCst);
    let out = mb.put(r1, [b'C'; 32], [9u8; 32], vec![0u8; 80]).unwrap();
    match out {
        PutOutcome::Stored { evicted } => assert_eq!(evicted, 1),
        other => panic!("expected Stored {{ evicted: 1 }}, got {:?}", other),
    }

    // r1 should now have only C.
    let r1_blobs = mb.fetch(r1).unwrap();
    assert_eq!(r1_blobs.len(), 1);
    assert_eq!(r1_blobs[0].content_id, [b'C'; 32]);
    // r2 still has B.
    let r2_blobs = mb.fetch(r2).unwrap();
    assert_eq!(r2_blobs.len(), 1);
    assert_eq!(r2_blobs[0].content_id, [b'B'; 32]);
}

/// audit regression test: random-receiver-flood attack
/// must NOT evict legitimate-but-fresh offline messages. Pre-fix, an
/// attacker could push the global quota over its cap and trigger
/// oldest-globally eviction, displacing data from honest receivers.
#[test]
fn phase650b_recent_blobs_protected_from_eviction_under_flood() {
    let cfg = MailboxConfig {
        quota_per_receiver_bytes: u64::MAX,
        quota_global_bytes: crate::billable_bytes(200),
        rate_limit_per_minute: 0,
        require_capability_token: false,
        quota_per_sender_bytes: u64::MAX,
        local_node_id: [0u8; 32],
        ..MailboxConfig::default()
    };
    let (mb, _tmp, clk) = fresh(cfg);
    let honest_recv = [1u8; 32];
    let attacker_target = [2u8; 32];

    // Honest receiver gets a fresh offline message at t=0.
    clk.store(0, Ordering::SeqCst);
    mb.put(honest_recv, [b'A'; 32], [9u8; 32], vec![0u8; 80])
        .unwrap();

    // Attacker, after a small delay (well within MIN_EVICTION_AGE
    // window), tries to flood: deposits to attacker_target until
    // global cap is hit.
    clk.store(60, Ordering::SeqCst); // 60 s — A is still fresh
    mb.put(attacker_target, [b'B'; 32], [99u8; 32], vec![0u8; 80])
        .unwrap();

    // Third put would push past 200 B; pre-fix, this would evict A
    // (the oldest globally). Post-fix, A is younger than
    // MIN_EVICTION_AGE_SECS (3600 s), so the new put is rejected
    // instead.
    clk.store(120, Ordering::SeqCst);
    let out = mb
        .put(attacker_target, [b'C'; 32], [99u8; 32], vec![0u8; 80])
        .unwrap();
    assert!(
        matches!(out, PutOutcome::QuotaGlobalExceeded { .. }),
        "expected attacker put rejected (recent blobs protected), got {:?}",
        out,
    );

    // Honest message preserved.
    let honest_blobs = mb.fetch(honest_recv).unwrap();
    assert_eq!(honest_blobs.len(), 1);
    assert_eq!(honest_blobs[0].content_id, [b'A'; 32]);
}

#[test]
fn t1_4_p1_global_quota_smaller_than_blob_rejects() {
    let cfg = MailboxConfig {
        quota_per_receiver_bytes: u64::MAX,
        quota_global_bytes: crate::billable_bytes(50),
        rate_limit_per_minute: 0,
        require_capability_token: false,
        quota_per_sender_bytes: u64::MAX,
        local_node_id: [0u8; 32],
        ..MailboxConfig::default()
    };
    let (mb, _tmp, _clk) = fresh(cfg);
    let out = mb
        .put([1u8; 32], [1u8; 32], [9u8; 32], vec![0u8; 100])
        .unwrap();
    match out {
        PutOutcome::QuotaGlobalExceeded {
            blob_size,
            cap_bytes,
        } => {
            // Both in billable bytes: the outcome reports what the put would
            // have COST, not the payload it carried (audit V-05).
            assert_eq!(blob_size, crate::billable_bytes(100));
            assert_eq!(cap_bytes, crate::billable_bytes(50));
        }
        other => panic!("expected QuotaGlobalExceeded, got {:?}", other),
    }
}

#[test]
fn t1_4_p1_ack_removes_blob_and_frees_quota() {
    let cfg = MailboxConfig {
        quota_per_receiver_bytes: crate::billable_bytes(100),
        rate_limit_per_minute: 0,
        require_capability_token: false,
        quota_per_sender_bytes: u64::MAX,
        local_node_id: [0u8; 32],
        ..MailboxConfig::default()
    };
    let (mb, _tmp, _clk) = fresh(cfg);
    let recv = [1u8; 32];
    let cid = [2u8; 32];

    mb.put(recv, cid, [9u8; 32], vec![0u8; 80]).unwrap();
    // Billable: payload plus the per-record overhead the quota now charges
    // (audit V-05).
    assert_eq!(mb.receiver_bytes(recv).unwrap(), crate::billable_bytes(80));

    let removed = mb.ack(recv, cid).unwrap();
    assert!(removed);
    // Back to EXACTLY zero, which is the property that matters most about
    // that change: charge one amount on the way in and refund a different one
    // on the way out, and the counters drift until the relay believes it is
    // full of blobs it no longer holds.
    assert_eq!(mb.receiver_bytes(recv).unwrap(), 0);
    assert!(mb.fetch(recv).unwrap().is_empty());

    // Idempotent re-ack.
    let removed_again = mb.ack(recv, cid).unwrap();
    assert!(!removed_again);
}

#[test]
fn t1_4_p1_ttl_prune_removes_only_expired() {
    let cfg = MailboxConfig {
        quota_per_receiver_bytes: u64::MAX,
        quota_global_bytes: u64::MAX,
        rate_limit_per_minute: 0,
        require_capability_token: false,
        quota_per_sender_bytes: u64::MAX,
        local_node_id: [0u8; 32],
        ttl_secs: 100, // short for test
    };
    let (mb, _tmp, clk) = fresh(cfg);
    let r = [1u8; 32];

    // t=1000: blob A.
    clk.store(1000, Ordering::SeqCst);
    mb.put(r, [b'A'; 32], [9u8; 32], vec![0u8; 10]).unwrap();
    // t=1050: blob B.
    clk.store(1050, Ordering::SeqCst);
    mb.put(r, [b'B'; 32], [9u8; 32], vec![0u8; 10]).unwrap();
    // t=1200: prune. Cutoff = 1200 - 100 = 1100. A (t=1000) expired, B (t=1050) expired.
    clk.store(1200, Ordering::SeqCst);
    let pruned = mb.prune_expired().unwrap();
    assert_eq!(pruned, 2);

    // t=1110: insert C. Then prune at t=1200: cutoff=1100, C survives.
    clk.store(1110, Ordering::SeqCst);
    mb.put(r, [b'C'; 32], [9u8; 32], vec![0u8; 10]).unwrap();
    clk.store(1200, Ordering::SeqCst);
    let pruned = mb.prune_expired().unwrap();
    assert_eq!(pruned, 0);
    let remaining = mb.fetch(r).unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].content_id, [b'C'; 32]);
}

#[test]
fn t1_4_p1_rate_limit_blocks_burst() {
    let cfg = MailboxConfig {
        quota_per_receiver_bytes: u64::MAX,
        quota_global_bytes: u64::MAX,
        rate_limit_per_minute: 3,
        require_capability_token: false,
        quota_per_sender_bytes: u64::MAX,
        local_node_id: [0u8; 32],
        ..MailboxConfig::default()
    };
    let (mb, _tmp, _clk) = fresh(cfg);
    let r = [1u8; 32];

    for i in 0..3 {
        let out = mb.put(r, [i as u8; 32], [9u8; 32], vec![0u8; 1]).unwrap();
        assert!(matches!(out, PutOutcome::Stored { .. }), "i={i}");
    }
    // 4th call: rate-limited. Blob is also NOT stored.
    let out = mb.put(r, [42u8; 32], [9u8; 32], vec![0u8; 1]).unwrap();
    assert_eq!(out, PutOutcome::RateLimited);
    let stored = mb.fetch(r).unwrap();
    assert_eq!(stored.len(), 3);
}

#[test]
fn t1_4_p1_blob_too_large_returns_error() {
    let (mb, _tmp, _clk) = fresh(MailboxConfig::default());
    let oversized = vec![0u8; (MAX_BLOB_BYTES + 1) as usize];
    match mb.put([1u8; 32], [2u8; 32], [3u8; 32], oversized) {
        Err(MailboxError::BlobTooLarge { actual, max }) => {
            assert_eq!(actual, MAX_BLOB_BYTES + 1);
            assert_eq!(max, MAX_BLOB_BYTES);
        }
        other => panic!("expected BlobTooLarge, got {:?}", other),
    }
}

#[test]
fn t1_4_p1_persistence_across_reopen() {
    let tmp = tempfile::tempdir().unwrap();
    let r = [7u8; 32];
    let cid = [8u8; 32];
    let sender = [9u8; 32];

    {
        let mb = Mailbox::open(tmp.path(), MailboxConfig::default()).unwrap();
        mb.put(r, cid, sender, b"persisted-blob".to_vec()).unwrap();
    } // drops the database handle

    // Reopen — blob must still be there.
    let mb2 = Mailbox::open(tmp.path(), MailboxConfig::default()).unwrap();
    let blobs = mb2.fetch(r).unwrap();
    assert_eq!(blobs.len(), 1);
    assert_eq!(blobs[0].blob, b"persisted-blob");
}

#[test]
fn t1_4_p1_fetch_returns_oldest_first() {
    let cfg = MailboxConfig {
        rate_limit_per_minute: 0,
        require_capability_token: false,
        quota_per_sender_bytes: u64::MAX,
        local_node_id: [0u8; 32],
        ..MailboxConfig::default()
    };
    let (mb, _tmp, clk) = fresh(cfg);
    let r = [1u8; 32];

    clk.store(100, Ordering::SeqCst);
    mb.put(r, [b'A'; 32], [9u8; 32], vec![0u8; 1]).unwrap();
    clk.store(50, Ordering::SeqCst);
    mb.put(r, [b'B'; 32], [9u8; 32], vec![0u8; 1]).unwrap();
    clk.store(75, Ordering::SeqCst);
    mb.put(r, [b'C'; 32], [9u8; 32], vec![0u8; 1]).unwrap();

    let blobs = mb.fetch(r).unwrap();
    assert_eq!(blobs.len(), 3);
    // Oldest first: B (50) -> C (75) -> A (100).
    assert_eq!(blobs[0].deposited_at, 50);
    assert_eq!(blobs[1].deposited_at, 75);
    assert_eq!(blobs[2].deposited_at, 100);
}

#[test]
fn t1_4_p1_stats_tracks_global_total() {
    let cfg = MailboxConfig {
        rate_limit_per_minute: 0,
        require_capability_token: false,
        quota_per_sender_bytes: u64::MAX,
        local_node_id: [0u8; 32],
        ..MailboxConfig::default()
    };
    let (mb, _tmp, _clk) = fresh(cfg);
    assert_eq!(mb.stats().unwrap().total_blob_bytes, 0);
    assert_eq!(mb.stats().unwrap().blob_count, 0);

    mb.put([1u8; 32], [1u8; 32], [9u8; 32], vec![0u8; 100])
        .unwrap();
    mb.put([2u8; 32], [2u8; 32], [9u8; 32], vec![0u8; 200])
        .unwrap();
    let s = mb.stats().unwrap();
    // Billable: what the two records COST the relay, not the payload they
    // carried (audit V-05). `blob_count` is the unchanged record count.
    assert_eq!(
        s.total_blob_bytes,
        crate::billable_bytes(100) + crate::billable_bytes(200)
    );
    assert_eq!(s.blob_count, 2);

    mb.ack([1u8; 32], [1u8; 32]).unwrap();
    let s = mb.stats().unwrap();
    assert_eq!(s.total_blob_bytes, crate::billable_bytes(200));
    assert_eq!(s.blob_count, 1);
}

#[test]
fn t1_4_p1_fetch_filters_by_receiver() {
    let cfg = MailboxConfig {
        rate_limit_per_minute: 0,
        require_capability_token: false,
        quota_per_sender_bytes: u64::MAX,
        local_node_id: [0u8; 32],
        ..MailboxConfig::default()
    };
    let (mb, _tmp, _clk) = fresh(cfg);

    mb.put([1u8; 32], [b'A'; 32], [9u8; 32], vec![1]).unwrap();
    mb.put([2u8; 32], [b'B'; 32], [9u8; 32], vec![2]).unwrap();
    mb.put([1u8; 32], [b'C'; 32], [9u8; 32], vec![3]).unwrap();

    let r1 = mb.fetch([1u8; 32]).unwrap();
    assert_eq!(r1.len(), 2);
    let r2 = mb.fetch([2u8; 32]).unwrap();
    assert_eq!(r2.len(), 1);
    let r3 = mb.fetch([99u8; 32]).unwrap();
    assert!(r3.is_empty());
}

// ── capability-token policy gate ─────────────────

/// Mint a valid Ed25519 capability token for a freshly-derived receiver.
/// Returns `(receiver_id, encoded_token_bytes)` so the test can use
/// the receiver_id as the PUT target.
fn mint_test_token(valid_from: u64, valid_until: u64) -> ([u8; 32], Vec<u8>) {
    use crate::capability::{
        ALGO_ED25519, MailboxCapabilityToken, TOKEN_VERSION, TokenBinding, signed_message_for,
    };
    use ed25519_dalek::{Signer, SigningKey};
    let mut seed = [0u8; 32];
    seed[0] = 0x77;
    let sk = SigningKey::from_bytes(&seed);
    let pk = sk.verifying_key().to_bytes().to_vec();
    let receiver_id = *blake3::hash(&pk).as_bytes();
    let msg = signed_message_for(TOKEN_VERSION, ALGO_ED25519, valid_from, valid_until, &pk);
    let sig = sk.sign(&msg).to_bytes().to_vec();
    let token = MailboxCapabilityToken {
        binding: TokenBinding::Unbound,
        issuer_algo: ALGO_ED25519,
        valid_from_unix: valid_from,
        valid_until_unix: valid_until,
        issuer_pk: pk,
        sig,
    };
    (receiver_id, token.encode())
}

#[test]
fn phase650b_316_capability_required_rejects_tokenless_put() {
    let cfg = MailboxConfig {
        rate_limit_per_minute: 0,
        require_capability_token: true,
        ..MailboxConfig::default()
    };
    let (mb, _tmp, _clk) = fresh(cfg);
    // clock pinned at 1_700_000_000. Token must not matter for this test —
    // we send a PUT with token=None and expect rejection.
    let outcome = mb
        .put_with_capability([11u8; 32], [22u8; 32], [33u8; 32], b"blob".to_vec(), None)
        .unwrap();
    assert_eq!(outcome, PutOutcome::CapabilityRequired);
}

#[test]
fn phase650b_316_capability_default_policy_accepts_tokenless_put() {
    // Default require_capability_token = false → backward-compat path:
    // tokenless puts go through.
    let cfg = MailboxConfig {
        rate_limit_per_minute: 0,
        ..MailboxConfig::default()
    };
    let (mb, _tmp, _clk) = fresh(cfg);
    let outcome = mb
        .put_with_capability([11u8; 32], [22u8; 32], [33u8; 32], b"blob".to_vec(), None)
        .unwrap();
    assert!(matches!(outcome, PutOutcome::Stored { .. }));
}

#[test]
fn phase650b_316_capability_required_accepts_valid_token() {
    let cfg = MailboxConfig {
        rate_limit_per_minute: 0,
        require_capability_token: true,
        ..MailboxConfig::default()
    };
    let (mb, _tmp, _clk) = fresh(cfg);
    // clock @ 1_700_000_000; mint token spanning that.
    let (receiver_id, token_bytes) = mint_test_token(1_700_000_000 - 60, 1_700_000_000 + 60);
    let outcome = mb
        .put_with_capability(
            receiver_id,
            [22u8; 32],
            [33u8; 32],
            b"blob".to_vec(),
            Some(&token_bytes),
        )
        .unwrap();
    assert!(matches!(outcome, PutOutcome::Stored { .. }));
}

#[test]
fn phase650b_316_capability_required_rejects_token_for_other_receiver() {
    let cfg = MailboxConfig {
        rate_limit_per_minute: 0,
        require_capability_token: true,
        ..MailboxConfig::default()
    };
    let (mb, _tmp, _clk) = fresh(cfg);
    let (_legit_receiver, token_bytes) = mint_test_token(1_700_000_000 - 60, 1_700_000_000 + 60);
    let rogue_receiver = [0xDDu8; 32];
    let outcome = mb
        .put_with_capability(
            rogue_receiver,
            [22u8; 32],
            [33u8; 32],
            b"blob".to_vec(),
            Some(&token_bytes),
        )
        .unwrap();
    assert_eq!(outcome, PutOutcome::CapabilityInvalid);
}

#[test]
fn phase650b_316_capability_required_rejects_expired_token() {
    let cfg = MailboxConfig {
        rate_limit_per_minute: 0,
        require_capability_token: true,
        ..MailboxConfig::default()
    };
    let (mb, _tmp, _clk) = fresh(cfg);
    // Token valid 1 hour in the past, expired 1 hour ago + skew.
    let (receiver_id, token_bytes) = mint_test_token(1_700_000_000 - 7200, 1_700_000_000 - 3600);
    let outcome = mb
        .put_with_capability(
            receiver_id,
            [22u8; 32],
            [33u8; 32],
            b"blob".to_vec(),
            Some(&token_bytes),
        )
        .unwrap();
    assert_eq!(outcome, PutOutcome::CapabilityInvalid);
}

#[test]
fn phase650b_316_capability_required_rejects_malformed_bytes() {
    let cfg = MailboxConfig {
        rate_limit_per_minute: 0,
        require_capability_token: true,
        ..MailboxConfig::default()
    };
    let (mb, _tmp, _clk) = fresh(cfg);
    let outcome = mb
        .put_with_capability(
            [11u8; 32],
            [22u8; 32],
            [33u8; 32],
            b"blob".to_vec(),
            Some(b"garbage-bytes"),
        )
        .unwrap();
    assert_eq!(outcome, PutOutcome::CapabilityInvalid);
}

#[test]
fn phase650b_316_capability_default_still_validates_provided_token() {
    // require=false BUT token provided: still validates malformed bytes
    // doesn't silently accept. Catches sender-side bugs early.
    let cfg = MailboxConfig {
        rate_limit_per_minute: 0,
        require_capability_token: false,
        quota_per_sender_bytes: u64::MAX,
        local_node_id: [0u8; 32],
        ..MailboxConfig::default()
    };
    let (mb, _tmp, _clk) = fresh(cfg);
    let outcome = mb
        .put_with_capability(
            [11u8; 32],
            [22u8; 32],
            [33u8; 32],
            b"blob".to_vec(),
            Some(b"garbage-bytes"),
        )
        .unwrap();
    assert_eq!(outcome, PutOutcome::CapabilityInvalid);
}

// ── per-sender quota + trust-class eviction ─────

#[test]
fn phase650b_316_per_sender_quota_blocks_when_exceeded() {
    let cfg = MailboxConfig {
        rate_limit_per_minute: 0,
        // Room for exactly one 60-byte record, in billable bytes — payload
        // plus the overhead the quota now charges (audit V-05).
        quota_per_sender_bytes: crate::billable_bytes(60),
        local_node_id: [0u8; 32], // tight cap
        ..MailboxConfig::default()
    };
    let (mb, _tmp, _clk) = fresh(cfg);
    let sender = [0xABu8; 32];
    // Two 60-byte puts from the same sender → the second does not fit.
    let r1 = mb.put([1u8; 32], [b'A'; 32], sender, vec![0; 60]).unwrap();
    assert!(matches!(r1, PutOutcome::Stored { .. }));
    let r2 = mb.put([2u8; 32], [b'B'; 32], sender, vec![0; 60]).unwrap();
    let billed = crate::billable_bytes(60);
    assert!(
        matches!(
            r2,
            PutOutcome::QuotaPerSenderExceeded {
                current_bytes,
                cap_bytes,
            } if current_bytes == billed && cap_bytes == billed
        ),
        "expected the sender cap to be full at one record, got {r2:?}"
    );
    // Different sender — accepted independently.
    let r3 = mb
        .put([3u8; 32], [b'C'; 32], [0xCDu8; 32], vec![0; 60])
        .unwrap();
    assert!(matches!(r3, PutOutcome::Stored { .. }));
}

#[test]
fn phase650b_316_per_sender_quota_decremented_on_ack() {
    let cfg = MailboxConfig {
        rate_limit_per_minute: 0,
        quota_per_sender_bytes: crate::billable_bytes(100),
        local_node_id: [0u8; 32],
        ..MailboxConfig::default()
    };
    let (mb, _tmp, _clk) = fresh(cfg);
    let sender = [0xABu8; 32];
    let r1 = mb.put([1u8; 32], [b'A'; 32], sender, vec![0; 60]).unwrap();
    assert!(matches!(r1, PutOutcome::Stored { .. }));
    // Second put would normally exceed, but ack first → frees sender quota.
    mb.ack([1u8; 32], [b'A'; 32]).unwrap();
    let r2 = mb.put([2u8; 32], [b'B'; 32], sender, vec![0; 60]).unwrap();
    assert!(
        matches!(r2, PutOutcome::Stored { .. }),
        "after ack the sender's quota must allow the next put"
    );
}

#[test]
fn phase650b_316_per_sender_quota_default_disabled() {
    // Default config has quota_per_sender_bytes = u64::MAX → many puts
    // from same sender go through unrestricted (modulo other quotas).
    let cfg = MailboxConfig {
        rate_limit_per_minute: 0,
        ..MailboxConfig::default()
    };
    let (mb, _tmp, _clk) = fresh(cfg);
    let sender = [0xABu8; 32];
    for i in 0..10u8 {
        let mut cid = [0u8; 32];
        cid[0] = i;
        let r = mb.put([i; 32], cid, sender, vec![0xCC; 1000]).unwrap();
        assert!(
            matches!(r, PutOutcome::Stored { .. }),
            "default policy must accept put {i}"
        );
    }
}

#[test]
fn phase650b_316_anon_pool_evicted_before_identified_under_global_pressure() {
    // Setup: tight global quota, two pools. Mint a valid token for the
    // identified sender; anonymous sender uses no token. Hit the global
    // cap; next put must displace the anon-pool entry first.
    use crate::capability::{
        ALGO_ED25519, MailboxCapabilityToken, TOKEN_VERSION, TokenBinding, signed_message_for,
    };
    use ed25519_dalek::{Signer, SigningKey};

    let cfg = MailboxConfig {
        rate_limit_per_minute: 0,
        // Room for exactly two 100-byte records, so the third has to displace
        // one — and the anon pool must go first. Sized in billable bytes,
        // which is what the quota charges (audit V-05).
        quota_global_bytes: 2 * crate::billable_bytes(100),
        ..MailboxConfig::default()
    };
    let (mb, _tmp, clk) = fresh(cfg);
    // Use clock advance to get past MIN_EVICTION_AGE_SECS so eviction is allowed.
    let mut seed = [0u8; 32];
    seed[0] = 0x33;
    let sk = SigningKey::from_bytes(&seed);
    let pk = sk.verifying_key().to_bytes().to_vec();
    let receiver_id = *blake3::hash(&pk).as_bytes();

    // 1. Put 1: anon-class, 100 bytes. Goes into anon pool.
    let r = mb
        .put_with_capability([1u8; 32], [b'A'; 32], [0xAAu8; 32], vec![0; 100], None)
        .unwrap();
    assert!(matches!(r, PutOutcome::Stored { .. }));

    // 2. Put 2: identified-class, 100 bytes. Goes into identified pool.
    let valid_from = 1_700_000_000;
    let valid_until = 1_700_000_000 + 60;
    let msg = signed_message_for(TOKEN_VERSION, ALGO_ED25519, valid_from, valid_until, &pk);
    let sig = sk.sign(&msg).to_bytes().to_vec();
    let token = MailboxCapabilityToken {
        binding: TokenBinding::Unbound,
        issuer_algo: ALGO_ED25519,
        valid_from_unix: valid_from,
        valid_until_unix: valid_until,
        issuer_pk: pk.clone(),
        sig,
    };
    let token_bytes = token.encode();
    let r = mb
        .put_with_capability(
            receiver_id,
            [b'B'; 32],
            [0xBBu8; 32],
            vec![0; 100],
            Some(&token_bytes),
        )
        .unwrap();
    assert!(matches!(r, PutOutcome::Stored { .. }));

    // 3. Advance clock past MIN_EVICTION_AGE_SECS so the entries can age out.
    clk.store(
        1_700_000_000 + crate::MIN_EVICTION_AGE_SECS + 1,
        std::sync::atomic::Ordering::SeqCst,
    );

    // 4. Mint a fresh token for the new clock and put 100 more bytes (any class) — total 300
    // exceeds 250 cap → eviction kicks in. Anon pool's [1u8;32]/'A' must
    // be the victim, NOT the identified [receiver_id]/'B'.
    let r = mb
        .put_with_capability([3u8; 32], [b'C'; 32], [0xCCu8; 32], vec![0; 100], None)
        .unwrap();
    assert!(
        matches!(r, PutOutcome::Stored { evicted: 1 }),
        "third put must evict exactly one entry to fit"
    );

    // The identified entry must still be present.
    let id_blobs = mb.fetch(receiver_id).unwrap();
    assert_eq!(id_blobs.len(), 1, "identified pool entry must survive");
    assert_eq!(id_blobs[0].content_id, [b'B'; 32]);

    // The anon entry must be gone.
    let anon_blobs = mb.fetch([1u8; 32]).unwrap();
    assert!(
        anon_blobs.is_empty(),
        "anon pool entry must have been evicted first"
    );
}

#[test]
fn phase650b_316_identified_pool_evicted_when_anon_empty() {
    // Same shape but no anon-class put — eviction falls back to identified
    // pool when global pressure hits (slice-3 invariant: anon-first but
    // not anon-only).
    let cfg = MailboxConfig {
        rate_limit_per_minute: 0,
        quota_global_bytes: crate::billable_bytes(150),
        ..MailboxConfig::default()
    };
    let (mb, _tmp, clk) = fresh(cfg);
    // Two trusted in-process puts (`put` defaults to Identified pool).
    mb.put([1u8; 32], [b'A'; 32], [0xAAu8; 32], vec![0; 100])
        .unwrap();
    clk.store(
        1_700_000_000 + crate::MIN_EVICTION_AGE_SECS + 1,
        std::sync::atomic::Ordering::SeqCst,
    );
    let r = mb
        .put([2u8; 32], [b'B'; 32], [0xBBu8; 32], vec![0; 100])
        .unwrap();
    assert!(
        matches!(r, PutOutcome::Stored { evicted: 1 }),
        "identified pool victim chosen when anon pool empty"
    );
}

#[test]
fn c13_fresh_anon_flood_falls_through_to_old_identified_victim() {
    // C-13: a flood of FRESH anonymous blobs must NOT bounce a legitimate
    // identified put while an OLD, evictable identified blob is sitting below
    // the global cap. Pre-fix the eviction loop only looked at the anon pool's
    // head; finding it too young (< MIN_EVICTION_AGE_SECS) it returned
    // QuotaGlobalExceeded and rejected the put. The loop must instead fall
    // through from the too-young anon head to the old identified head.
    let cfg = MailboxConfig {
        rate_limit_per_minute: 0,
        // Exactly two 100-byte records, so the third forces the eviction loop
        // to choose. Billable bytes, matching what the quota charges
        // (audit V-05).
        quota_global_bytes: 2 * crate::billable_bytes(100),
        ..MailboxConfig::default()
    };
    let (mb, _tmp, clk) = fresh(cfg);
    let t0 = 1_700_000_000u64;
    clk.store(t0, Ordering::SeqCst);

    // 1. Old identified blob (`put` → Identified pool), deposited at t0.
    mb.put([1u8; 32], [b'O'; 32], [0x11u8; 32], vec![0; 100])
        .unwrap();

    // 2. Jump past MIN_EVICTION_AGE_SECS — the identified blob is now old
    //    enough to evict — then deposit a FRESH anon blob, younger than the
    //    age guard.
    let t1 = t0 + crate::MIN_EVICTION_AGE_SECS + 100;
    clk.store(t1, Ordering::SeqCst);
    mb.put_with_capability([2u8; 32], [b'A'; 32], [0x22u8; 32], vec![0; 100], None)
        .unwrap();

    // 3. New identified put overflows the 250-byte cap (100+100+100=300).
    //    Pre-fix: fresh anon head → age guard → QuotaGlobalExceeded (rejected).
    //    Post-fix: fall through to the old identified victim → Stored.
    let r = mb
        .put([3u8; 32], [b'N'; 32], [0x33u8; 32], vec![0; 100])
        .unwrap();
    assert!(
        matches!(r, PutOutcome::Stored { evicted: 1 }),
        "fresh anon flood must not reject a legit identified put while an old \
         identified blob is evictable; got {r:?}"
    );

    // The OLD identified blob was the victim; the fresh anon blob survives
    // (too young to evict); the new identified blob is stored.
    assert!(
        mb.fetch([1u8; 32]).unwrap().is_empty(),
        "old identified blob must be evicted"
    );
    assert_eq!(
        mb.fetch([2u8; 32]).unwrap().len(),
        1,
        "fresh anon blob must survive (younger than the age guard)"
    );
    assert_eq!(
        mb.fetch([3u8; 32]).unwrap().len(),
        1,
        "new identified blob must be stored"
    );
}

#[test]
fn phase650b_316_capability_required_uses_identified_pool() {
    // When `require_capability_token = true` is enforced, every accepted
    // put has a verified token — all go into Identified pool. Confirm
    // by exhausting global quota and verifying eviction comes from
    // Identified (anon would be empty in this scenario).
    use crate::capability::{
        ALGO_ED25519, MailboxCapabilityToken, TOKEN_VERSION, TokenBinding, signed_message_for,
    };
    use ed25519_dalek::{Signer, SigningKey};

    let cfg = MailboxConfig {
        rate_limit_per_minute: 0,
        quota_global_bytes: crate::billable_bytes(150),
        require_capability_token: true,
        ..MailboxConfig::default()
    };
    let (mb, _tmp, clk) = fresh(cfg);
    let mut seed = [0u8; 32];
    seed[0] = 0x77;
    let sk = SigningKey::from_bytes(&seed);
    let pk = sk.verifying_key().to_bytes().to_vec();
    let receiver_id = *blake3::hash(&pk).as_bytes();
    let valid_from = 1_700_000_000 - 60;
    let valid_until = 1_700_000_000 + crate::MIN_EVICTION_AGE_SECS + 120;
    let msg = signed_message_for(TOKEN_VERSION, ALGO_ED25519, valid_from, valid_until, &pk);
    let sig = sk.sign(&msg).to_bytes().to_vec();
    let token_bytes = MailboxCapabilityToken {
        binding: TokenBinding::Unbound,
        issuer_algo: ALGO_ED25519,
        valid_from_unix: valid_from,
        valid_until_unix: valid_until,
        issuer_pk: pk.clone(),
        sig,
    }
    .encode();

    let r1 = mb
        .put_with_capability(
            receiver_id,
            [b'A'; 32],
            [0xAAu8; 32],
            vec![0; 100],
            Some(&token_bytes),
        )
        .unwrap();
    assert!(matches!(r1, PutOutcome::Stored { .. }));
    clk.store(
        1_700_000_000 + crate::MIN_EVICTION_AGE_SECS + 1,
        std::sync::atomic::Ordering::SeqCst,
    );
    let r2 = mb
        .put_with_capability(
            receiver_id,
            [b'B'; 32],
            [0xBBu8; 32],
            vec![0; 100],
            Some(&token_bytes),
        )
        .unwrap();
    // Both are identified-class; eviction picks oldest identified.
    assert!(matches!(r2, PutOutcome::Stored { evicted: 1 }));
    let surviving = mb.fetch(receiver_id).unwrap();
    assert_eq!(surviving.len(), 1);
    assert_eq!(surviving[0].content_id, [b'B'; 32]);
}

/// A byte quota must bound the RECORD count, not just the payload total.
///
/// It used to charge the payload and nothing else, and a 1-byte blob is legal.
/// A record is not 1 byte on disk — it is a primary key, a 44-byte record
/// header, a 64-byte blobs key, a 72-byte eviction key and redb's page
/// overhead around all of it. So a quota sized in payload bytes admitted
/// roughly as many records as it had bytes, and the relay ran out of DISK and
/// I/O long before it ran out of quota (audit V-05).
///
/// Pinned as a RATIO rather than an exact number: the point is the order of
/// magnitude between "one record per byte of quota" and "one record per
/// couple of hundred", not the precise overhead constant.
#[test]
fn a_byte_quota_bounds_the_record_count_not_only_the_payload() {
    // Small enough that the loop is quick even when the accounting is WRONG
    // (payload-only admits one record per byte), which matters: a probe that
    // reverts the fix must fail fast rather than run for minutes.
    const CAP: u64 = 4 * 1024;
    let cfg = MailboxConfig {
        quota_per_receiver_bytes: CAP,
        rate_limit_per_minute: 0,
        quota_per_sender_bytes: u64::MAX,
        quota_global_bytes: u64::MAX,
        ..MailboxConfig::default()
    };
    let (mb, _tmp, _clk) = fresh(cfg);
    let recv = [7u8; 32];

    // Deposit one-byte blobs under distinct content ids until the cap says no.
    let mut stored = 0u64;
    for i in 0..(CAP + 16) {
        // Bounded independently of the cap so a broken accounting cannot turn
        // this test into a long-running one.
        if stored > 512 {
            break;
        }
        let mut cid = [0u8; 32];
        cid[..8].copy_from_slice(&i.to_be_bytes());
        match mb.put(recv, cid, [9u8; 32], vec![0u8; 1]).unwrap() {
            PutOutcome::Stored { .. } => stored += 1,
            _ => break,
        }
    }

    let payload_only_would_admit = CAP; // 1 byte charged per record
    assert!(
        stored * 8 < payload_only_would_admit,
        "a {CAP}-byte cap admitted {stored} one-byte records — payload-only \
         accounting would have admitted about {payload_only_would_admit}, and \
         that is the amplification"
    );
    assert!(stored > 0, "the cap must still admit SOME records");
}

// ── Anonymous ingress budget (audit V-04) ───────────────────────────────────
//
// An anonymous deposit reaches the relay with `src_node_id == [0u8; 32]` — the
// transport zeroes it precisely so the relay CANNOT know who sent it — and the
// relay handed that marker to the per-sender byte quota as if it were a sender.
// So every anonymous depositor on the network shared one bucket.
//
// The helper below floods a receiver anonymously, the way the transport
// actually presents such deposits, and reports how far it got.

/// Deposit anonymous 64-byte blobs at `recv` until the relay refuses one.
///
/// Returns `(stored, refused)`. The iteration count is bounded well below any
/// cap these tests configure so that a regression which lets anonymous ingress
/// run away fails FAST instead of running for minutes.
fn flood_anonymously(mb: &Mailbox, recv: [u8; 32], tag: u8) -> (u64, bool) {
    let mut stored = 0u64;
    for i in 0..256u64 {
        let mut cid = [tag; 32];
        cid[..8].copy_from_slice(&i.to_be_bytes());
        // `[0u8; 32]`: not a choice the depositor makes, and not an identity —
        // it is what an anonymous delivery carries in place of one.
        match mb
            .put_classified(recv, cid, [0u8; 32], vec![0u8; 64], TrustClass::Anonymous)
            .unwrap()
        {
            PutOutcome::Stored { .. } => stored += 1,
            _ => return (stored, true),
        }
    }
    (stored, false)
}

/// Saturating anonymous ingress must not close the door on an identified sender.
///
/// This is the guarantee, stated without reference to how the budget is sized:
/// whatever anonymous depositors do to a receiver, a sender that identified
/// itself can still reach that same receiver. Before the fix the two shared the
/// receiver's whole window, so filling it anonymously — which needs no identity,
/// no capability token and no invitation — locked the identified sender out.
#[test]
fn anon_saturation_does_not_block_an_identified_sender() {
    // 8 KiB window: big enough to hold many records, small enough that the
    // flood terminates immediately even when the budget is (wrongly) the
    // receiver's entire window.
    const CAP: u64 = 8 * 1024;
    let cfg = MailboxConfig {
        quota_per_receiver_bytes: CAP,
        rate_limit_per_minute: 0,
        // Deliberately DISABLED. The per-sender quota is what used to bound
        // anonymous ingress — by accident, through the `[0u8; 32]` marker.
        // Switching it off leaves the anonymous budget itself as the only
        // thing that can stop the flood, which is what this test is about.
        quota_per_sender_bytes: u64::MAX,
        quota_global_bytes: u64::MAX,
        ..MailboxConfig::default()
    };
    let (mb, _tmp, _clk) = fresh(cfg);
    let recv = [7u8; 32];

    let (anon_stored, anon_refused) = flood_anonymously(&mb, recv, 0xA0);
    assert!(anon_stored > 0, "anonymous ingress must admit SOME deposits");
    assert!(
        anon_refused,
        "anonymous ingress ran to the iteration bound without ever being \
         refused — it has no ceiling of its own"
    );

    // The point of the whole change: this must still succeed.
    let out = mb
        .put_classified(
            recv,
            [0xEEu8; 32],
            [0xABu8; 32],
            vec![0u8; 64],
            TrustClass::Identified,
        )
        .unwrap();
    assert!(
        matches!(out, PutOutcome::Stored { .. }),
        "an identified sender was turned away by a receiver whose window had \
         been filled ANONYMOUSLY — the two must not share one budget: got {out:?}"
    );
}

/// The anonymous entrance is not one bucket for the whole network.
///
/// Anonymous deposits have no sender, so charging them to a per-SENDER quota
/// charged them all to the same row, and one depositor's traffic — at any
/// receiver — spent the entire network's anonymous allowance. Anonymous bytes
/// are now counted per RECEIVER, which is the only axis that exists when there
/// is no sender to count by, so a flood aimed at one receiver stays there.
#[test]
fn anon_flood_at_one_receiver_does_not_close_the_door_at_another() {
    let cfg = MailboxConfig {
        quota_per_receiver_bytes: 8 * 1024,
        rate_limit_per_minute: 0,
        // Tight: room for about four 64-byte records. This is the bucket the
        // `[0u8; 32]` marker used to land in, shared by every anonymous
        // depositor on the network.
        quota_per_sender_bytes: crate::billable_bytes(64) * 4,
        quota_global_bytes: u64::MAX,
        ..MailboxConfig::default()
    };
    let (mb, _tmp, _clk) = fresh(cfg);
    let victim = [1u8; 32];
    let bystander = [2u8; 32];

    let (stored, refused) = flood_anonymously(&mb, victim, 0xB0);
    assert!(stored > 0 && refused, "the flood must fill and then be refused");

    // A different receiver's anonymous slice is untouched by that flood.
    let out = mb
        .put_classified(
            bystander,
            [0xCCu8; 32],
            [0u8; 32],
            vec![0u8; 64],
            TrustClass::Anonymous,
        )
        .unwrap();
    assert!(
        matches!(out, PutOutcome::Stored { .. }),
        "an anonymous deposit to an UNRELATED receiver was refused because a \
         different receiver had been flooded — the anonymous entrance is still \
         one shared bucket: got {out:?}"
    );
    assert_eq!(
        mb.receiver_anon_bytes(bystander).unwrap(),
        crate::billable_bytes(64),
        "the bystander's anonymous slice should hold exactly that one record"
    );
}

/// The anonymous budget is a boundary that RELEASES — acking gives it back.
///
/// The counter is incremented in one place and decremented in three (ack, TTL
/// prune, eviction), and a budget that is charged but never refunded is a
/// slower version of the same denial of service: the anonymous entrance shuts
/// permanently and the relay never notices, because the blobs it thinks it is
/// holding are gone. Pinned as behaviour — refused, then ack, then accepted
/// again — and as the exact-zero counter after everything is drained.
#[test]
fn anon_budget_is_refunded_on_ack_and_reopens_the_entrance() {
    let cfg = MailboxConfig {
        quota_per_receiver_bytes: 8 * 1024,
        rate_limit_per_minute: 0,
        quota_per_sender_bytes: u64::MAX,
        quota_global_bytes: u64::MAX,
        ..MailboxConfig::default()
    };
    let (mb, _tmp, _clk) = fresh(cfg);
    let recv = [3u8; 32];

    let (stored, refused) = flood_anonymously(&mb, recv, 0xD0);
    assert!(stored > 0 && refused, "the flood must fill and then be refused");
    let saturated = mb.receiver_anon_bytes(recv).unwrap();
    assert!(saturated > 0, "the anonymous slice must be accounted");

    // Confirm the entrance really is shut before acking anything.
    let mut blocked_cid = [0xD0u8; 32];
    blocked_cid[..8].copy_from_slice(&999u64.to_be_bytes());
    let out = mb
        .put_classified(recv, blocked_cid, [0u8; 32], vec![0u8; 64], TrustClass::Anonymous)
        .unwrap();
    assert!(
        !matches!(out, PutOutcome::Stored { .. }),
        "the anonymous slice was supposed to be full: got {out:?}"
    );

    // Take one blob off the receiver's hands; the room must come back.
    let mut first_cid = [0xD0u8; 32];
    first_cid[..8].copy_from_slice(&0u64.to_be_bytes());
    assert!(mb.ack(recv, first_cid).unwrap(), "the first blob must exist");
    assert_eq!(
        mb.receiver_anon_bytes(recv).unwrap(),
        saturated - crate::billable_bytes(64),
        "ack must refund exactly what the put charged"
    );
    let out = mb
        .put_classified(recv, blocked_cid, [0u8; 32], vec![0u8; 64], TrustClass::Anonymous)
        .unwrap();
    assert!(
        matches!(out, PutOutcome::Stored { .. }),
        "acking a blob did not reopen the anonymous entrance: got {out:?}"
    );

    // Drain everything: the slice must return to EXACTLY zero. A budget that
    // settles at a nonzero floor loses a little capacity on every cycle.
    for blob in mb.fetch(recv).unwrap() {
        assert!(mb.ack(recv, blob.content_id).unwrap());
    }
    assert_eq!(
        mb.receiver_anon_bytes(recv).unwrap(),
        0,
        "the anonymous slice must be empty once every blob has been acked"
    );
    assert_eq!(mb.receiver_bytes(recv).unwrap(), 0);
}

// ── audit V-05: the anonymous-ingress counter is reconciled at open ────────

/// Read `sender_bytes[sender]` straight out of the DB — no accessor exists
/// because production code has no reason to read it outside a put.
fn sender_bytes_row(mb: &Mailbox, sender: [u8; 32]) -> u64 {
    let txn = mb.db.begin_read().unwrap();
    let t = txn.open_table(TABLE_SENDER_BYTES).unwrap();
    t.get(sender.as_slice())
        .unwrap()
        .map(|v| v.value())
        .unwrap_or(0)
}

/// Overwrite the anonymous counter behind the mailbox's back, reproducing what
/// a database written by a build without `anon_receiver_bytes_v1` looks like
/// when a build that HAS the table opens it: anonymous blobs are held, the
/// counter says otherwise.
fn scribble_anon_counter(dir: &std::path::Path, rows: &[([u8; 32], u64)], wipe_first: bool) {
    let db = Database::create(dir.join("mailbox").join("blobs.db")).unwrap();
    let txn = db.begin_write().unwrap();
    {
        let mut t = txn.open_table(TABLE_ANON_RECEIVER_BYTES).unwrap();
        if wipe_first {
            let keys: Vec<Vec<u8>> = t
                .iter()
                .unwrap()
                .map(|e| e.unwrap().0.value().to_vec())
                .collect();
            for k in keys {
                t.remove(k.as_slice()).unwrap();
            }
        }
        for (recv, bytes) in rows {
            t.insert(recv.as_slice(), *bytes).unwrap();
        }
    }
    txn.commit().unwrap();
}

fn reopen(dir: &std::path::Path, cfg: MailboxConfig) -> Mailbox {
    Mailbox::open(dir, cfg).unwrap()
}

/// A counter that under-reports (the pre-fix state for any DB written before
/// the table existed) must come back to the truth at open, not stay wrong
/// until the blobs age out over the TTL. Under-reporting is the direction that
/// matters: it lets anonymous ingress overshoot the slice carved out of the
/// receiver's window.
#[test]
fn v05_anon_counter_under_reporting_is_rebuilt_at_open() {
    let cfg = MailboxConfig {
        rate_limit_per_minute: 0,
        ..MailboxConfig::default()
    };
    let (mb, tmp, _clk) = fresh(cfg.clone());
    let recv = [0xA1u8; 32];
    let other = [0xA2u8; 32];
    for i in 0..3u8 {
        let mut cid = [0u8; 32];
        cid[0] = i;
        mb.put_classified(recv, cid, [0u8; 32], vec![0u8; 64], TrustClass::Anonymous)
            .unwrap();
    }
    mb.put_classified(other, [9u8; 32], [0u8; 32], vec![0u8; 32], TrustClass::Anonymous)
        .unwrap();
    let truth_recv = mb.receiver_anon_bytes(recv).unwrap();
    let truth_other = mb.receiver_anon_bytes(other).unwrap();
    assert_eq!(truth_recv, billable_bytes(64) * 3);
    assert_eq!(truth_other, billable_bytes(32));
    drop(mb);

    // Every anonymous byte now uncounted, exactly as a pre-table DB presents.
    scribble_anon_counter(tmp.path(), &[], true);
    {
        let mb = reopen(tmp.path(), cfg.clone());
        assert_eq!(
            mb.receiver_anon_bytes(recv).unwrap(),
            truth_recv,
            "opening a mailbox whose anonymous counter was written by a build \
             without the table must rebuild it from the records actually held"
        );
        assert_eq!(mb.receiver_anon_bytes(other).unwrap(), truth_other);
    }
}

/// Drift in the OTHER direction — a row claiming bytes for a receiver that
/// holds no anonymous records at all — must be removed, not merely left. A
/// leftover row silently spends that receiver's anonymous slice forever.
#[test]
fn v05_anon_counter_over_reporting_and_orphan_rows_are_cleared() {
    let cfg = MailboxConfig {
        rate_limit_per_minute: 0,
        ..MailboxConfig::default()
    };
    let (mb, tmp, _clk) = fresh(cfg.clone());
    let recv = [0xB1u8; 32];
    let ghost = [0xB2u8; 32];
    mb.put_classified(recv, [1u8; 32], [0u8; 32], vec![0u8; 64], TrustClass::Anonymous)
        .unwrap();
    let truth = mb.receiver_anon_bytes(recv).unwrap();
    drop(mb);

    scribble_anon_counter(
        tmp.path(),
        &[(recv, 99_999_999), (ghost, 12_345)],
        false,
    );
    let mb = reopen(tmp.path(), cfg);
    assert_eq!(
        mb.receiver_anon_bytes(recv).unwrap(),
        truth,
        "an inflated row must be corrected down to what is actually held"
    );
    assert_eq!(
        mb.receiver_anon_bytes(ghost).unwrap(),
        0,
        "a row for a receiver holding no anonymous records must be REMOVED, \
         not left to spend its slice forever"
    );
}

/// The rebuild must not disturb the identified pool: a real sender's row is
/// untouched, and only the all-zero MARKER row is dropped.
#[test]
fn v05_rebuild_drops_only_the_zero_sender_marker_row() {
    let cfg = MailboxConfig {
        rate_limit_per_minute: 0,
        ..MailboxConfig::default()
    };
    let (mb, tmp, _clk) = fresh(cfg.clone());
    let real_sender = [0xC7u8; 32];
    mb.put([0xC1u8; 32], [1u8; 32], real_sender, vec![0u8; 64])
        .unwrap();
    let real_row = sender_bytes_row(&mb, real_sender);
    assert!(real_row > 0);
    drop(mb);

    // Plant the legacy shared-bucket row an older build would have left.
    {
        let db = Database::create(tmp.path().join("mailbox").join("blobs.db")).unwrap();
        let txn = db.begin_write().unwrap();
        {
            let mut t = txn.open_table(TABLE_SENDER_BYTES).unwrap();
            t.insert([0u8; 32].as_slice(), 7_000_000u64).unwrap();
        }
        txn.commit().unwrap();
    }

    let mb = reopen(tmp.path(), cfg);
    assert_eq!(
        sender_bytes_row(&mb, [0u8; 32]),
        0,
        "the no-sender marker's per-sender row is obsolete and must be dropped"
    );
    assert_eq!(
        sender_bytes_row(&mb, real_sender),
        real_row,
        "a real sender's quota state must survive the rebuild untouched"
    );
}

/// CONTROL: the rebuild is unconditional, so it must be a no-op on a healthy
/// database. Without this, the three tests above would pass just as well if it
/// zeroed everything or double-counted.
#[test]
fn v05_control_rebuild_is_a_noop_on_a_consistent_database() {
    let cfg = MailboxConfig {
        rate_limit_per_minute: 0,
        ..MailboxConfig::default()
    };
    let (mb, tmp, _clk) = fresh(cfg.clone());
    let recv = [0xD1u8; 32];
    for i in 0..4u8 {
        let mut cid = [0u8; 32];
        cid[0] = i;
        mb.put_classified(recv, cid, [0u8; 32], vec![0u8; 48], TrustClass::Anonymous)
            .unwrap();
    }
    mb.put([0xD2u8; 32], [7u8; 32], [0xD3u8; 32], vec![0u8; 48])
        .unwrap();
    let anon_before = mb.receiver_anon_bytes(recv).unwrap();
    let ident_before = sender_bytes_row(&mb, [0xD3u8; 32]);
    drop(mb);

    // Reopen twice: idempotence, not just correctness on the first pass.
    let mb = reopen(tmp.path(), cfg.clone());
    assert_eq!(mb.receiver_anon_bytes(recv).unwrap(), anon_before);
    drop(mb);
    let mb = reopen(tmp.path(), cfg);
    assert_eq!(
        mb.receiver_anon_bytes(recv).unwrap(),
        anon_before,
        "the rebuild must be idempotent, not accumulate on each open"
    );
    assert_eq!(sender_bytes_row(&mb, [0xD3u8; 32]), ident_before);
}

// ── audit V-05 (adjacent): a valid token cannot conjure a sender ───────────

/// An anonymous deposit (`sender == [0u8; 32]`, the transport's no-sender
/// MARKER) carrying a VALID capability token used to verify, be classified
/// `Identified`, and be charged to `sender_bytes[[0u8; 32]]` — the single
/// network-wide bucket the receiver-keyed anonymous budget exists to replace.
/// One depositor filling it would close the door for every other tokened
/// anonymous sender.
#[test]
fn v05_zero_sender_cannot_be_charged_to_the_shared_marker_bucket() {
    let cfg = MailboxConfig {
        rate_limit_per_minute: 0,
        ..MailboxConfig::default()
    };
    let (mb, _tmp, _clk) = fresh(cfg);
    let recv = [0xE1u8; 32];

    // The classification a verified token produces, with no sender to charge.
    let out = mb
        .put_classified(recv, [1u8; 32], [0u8; 32], vec![0u8; 64], TrustClass::Identified)
        .unwrap();
    assert!(matches!(out, PutOutcome::Stored { .. }));

    assert_eq!(
        sender_bytes_row(&mb, [0u8; 32]),
        0,
        "the no-sender marker must never be charged as if it were a sender — \
         that is the shared bucket every anonymous depositor used to contend for"
    );
    assert_eq!(
        mb.receiver_anon_bytes(recv).unwrap(),
        billable_bytes(64),
        "with no sender to charge, the deposit belongs to the receiver-keyed \
         anonymous budget"
    );
}

/// CONTROL: a deposit that DOES carry a sender is still identified — charged
/// per-sender and parked in the identified eviction pool. Otherwise the guard
/// above could be reclassifying everything.
#[test]
fn v05_control_a_real_sender_is_still_identified() {
    let cfg = MailboxConfig {
        rate_limit_per_minute: 0,
        ..MailboxConfig::default()
    };
    let (mb, _tmp, _clk) = fresh(cfg);
    let recv = [0xF1u8; 32];
    let sender = [0xF2u8; 32];

    mb.put_classified(recv, [1u8; 32], sender, vec![0u8; 64], TrustClass::Identified)
        .unwrap();
    assert_eq!(sender_bytes_row(&mb, sender), billable_bytes(64));
    assert_eq!(
        mb.receiver_anon_bytes(recv).unwrap(),
        0,
        "an identified deposit must not spend the receiver's anonymous slice"
    );
}

// ── report7 V-01: the fetch batch is bounded in BYTES, not only in records ───

/// Config for the megabyte-blob tests: the per-sender default (10 MiB) and the
/// rate limiter would both stop the deposits long before the fetch ceiling is
/// reached, and neither is what these tests are about.
fn bulk_cfg() -> MailboxConfig {
    MailboxConfig {
        rate_limit_per_minute: 0,
        quota_per_sender_bytes: u64::MAX,
        ..MailboxConfig::default()
    }
}

/// Deposit `n` blobs of exactly [`MAX_BLOB_BYTES`] for `recv`, each with a
/// distinct content_id and a distinct deposit time so the oldest-first order
/// is total. Returns the content_ids in deposit order.
fn deposit_megabyte_blobs(mb: &Mailbox, clk: &Arc<AtomicU64>, recv: [u8; 32], n: u8) -> Vec<[u8; 32]> {
    let sender = [0x5Au8; 32];
    let mut ids = Vec::with_capacity(n as usize);
    for i in 0..n {
        let mut cid = [0u8; 32];
        cid[0] = i;
        clk.fetch_add(1, Ordering::SeqCst);
        mb.put(recv, cid, sender, vec![0u8; MAX_BLOB_BYTES as usize])
            .unwrap();
        ids.push(cid);
    }
    ids
}

/// 17 × 1 MiB is the smallest backlog whose sum passes 16 MiB, the size every
/// FFI/Flutter consumer allocated for a fetch. The count cap ([`MAX_FETCH_COUNT`]
/// = 1024) does not see that at all: it would hand back all 17 — and, against a
/// mailbox filled to the default 100 MiB receiver quota, all hundred megabytes
/// of it, materialised in the relay's heap on EVERY fetch of the drain.
#[test]
fn v01_fetch_batch_stays_under_the_byte_ceiling_with_seventeen_megabyte_blobs() {
    let (mb, _tmp, clk) = fresh(bulk_cfg());
    let recv = [0x17u8; 32];
    let ids = deposit_megabyte_blobs(&mb, &clk, recv, 17);

    let batch = mb.fetch(recv).unwrap();
    let total: u64 = batch.iter().map(|b| b.blob.len() as u64).sum();

    assert!(
        total <= MAX_FETCH_BYTES,
        "a fetch batch must never exceed MAX_FETCH_BYTES ({MAX_FETCH_BYTES}), got {total}"
    );
    assert!(!batch.is_empty(), "the batch must make progress");
    assert!(
        batch.len() < ids.len(),
        "17 MiB cannot fit under an 8 MiB ceiling — the count cap alone would \
         have returned all {} records ({} bytes)",
        ids.len(),
        ids.len() as u64 * MAX_BLOB_BYTES
    );
    // The ceiling is a whole number of worst-case blobs, so the cut is exact.
    assert_eq!(batch.len(), (MAX_FETCH_BYTES / MAX_BLOB_BYTES) as usize);
    // Oldest-first is preserved across the cut.
    for (i, b) in batch.iter().enumerate() {
        assert_eq!(b.content_id, ids[i], "batch must stay oldest-first");
    }
}

/// The other half of the contract: nothing is LOST to the ceiling. A backlog
/// larger than one batch drains over several ack-then-fetch rounds, every round
/// stays under the ceiling, and no round fails — the wedge in the report was a
/// receiver that could neither read the batch nor ack it (ack keys off a
/// content_id only a successful fetch reveals), leaving the box locked until
/// the 7-day TTL.
#[test]
fn v01_seventeen_megabyte_blobs_drain_over_several_fetches_none_failing() {
    let (mb, _tmp, clk) = fresh(bulk_cfg());
    let recv = [0x18u8; 32];
    let deposited = deposit_megabyte_blobs(&mb, &clk, recv, 17);

    let mut drained: Vec<[u8; 32]> = Vec::new();
    let mut rounds = 0usize;
    loop {
        let batch = mb.fetch(recv).unwrap();
        if batch.is_empty() {
            break;
        }
        rounds += 1;
        assert!(
            rounds <= deposited.len(),
            "drain is not converging — {rounds} rounds for {} records",
            deposited.len()
        );
        let total: u64 = batch.iter().map(|b| b.blob.len() as u64).sum();
        assert!(
            total <= MAX_FETCH_BYTES,
            "round {rounds} returned {total} bytes, over the ceiling"
        );
        for b in batch {
            assert_eq!(b.blob.len(), MAX_BLOB_BYTES as usize);
            assert!(mb.ack(recv, b.content_id).unwrap(), "ack must remove");
            drained.push(b.content_id);
        }
    }

    let mut want = deposited.clone();
    want.sort_unstable();
    let mut got = drained.clone();
    got.sort_unstable();
    assert_eq!(got, want, "every deposited blob must come back exactly once");
    assert_eq!(
        rounds, 3,
        "17 MiB under an 8 MiB ceiling is 8 + 8 + 1 — three fetches"
    );
    assert_eq!(mb.receiver_bytes(recv).unwrap(), 0, "quota fully released");
}

/// Write a record straight into the blobs table, bypassing `put`'s
/// [`MAX_BLOB_BYTES`] gate. Reproduces a record that no current `put` would
/// accept — a legacy row, or one written by a build with a larger cap.
fn scribble_oversized_record(dir: &std::path::Path, recv: [u8; 32], cid: [u8; 32], len: usize) {
    let db = Database::create(dir.join("mailbox").join("blobs.db")).unwrap();
    let txn = db.begin_write().unwrap();
    {
        let mut t = txn.open_table(TABLE_BLOBS).unwrap();
        let rec = encode_record(&[0x99u8; 32], 1, &vec![0u8; len]);
        t.insert(make_key(&recv, &cid).as_slice(), rec.as_slice())
            .unwrap();
    }
    txn.commit().unwrap();
}

/// The head of an oldest-first queue must ALWAYS be emitted, even when it alone
/// exceeds the ceiling. Without that clause a single oversized record parks at
/// the head forever and starves every deliverable blob behind it — the exact
/// wedge the byte ceiling exists to prevent, reintroduced by the ceiling
/// itself. (The same rule already guards the onion FETCH packer and the IPC
/// response packer.)
#[test]
fn v01_head_record_is_emitted_even_when_it_alone_exceeds_the_ceiling() {
    let cfg = bulk_cfg();
    let (mb, tmp, clk) = fresh(cfg.clone());
    let recv = [0x19u8; 32];
    // A deliverable blob queued BEHIND the oversized one: it is what a wedge
    // would starve.
    clk.store(500, Ordering::SeqCst);
    mb.put(recv, [0xEEu8; 32], [0x5Au8; 32], vec![7u8; 128])
        .unwrap();
    drop(mb);

    // deposited_at = 1, older than the 128-byte blob above → head of the queue.
    let huge = (MAX_FETCH_BYTES + 1) as usize;
    scribble_oversized_record(tmp.path(), recv, [0xAAu8; 32], huge);

    let mb = reopen(tmp.path(), cfg);
    let batch = mb.fetch(recv).unwrap();
    assert!(
        !batch.is_empty(),
        "an oversized head record must still be emitted — otherwise it wedges \
         the queue until the 7-day TTL"
    );
    assert_eq!(batch[0].content_id, [0xAAu8; 32]);
    assert_eq!(batch[0].blob.len(), huge);
    assert_eq!(
        batch.len(),
        1,
        "the ceiling still stops the batch after the mandatory head record"
    );

    // And once the head is acked the blob behind it is served — progress.
    assert!(mb.ack(recv, [0xAAu8; 32]).unwrap());
    let next = mb.fetch(recv).unwrap();
    assert_eq!(next.len(), 1);
    assert_eq!(next[0].content_id, [0xEEu8; 32]);
}

/// CONTROL: the byte ceiling must not shorten batches that fit. A thousand tiny
/// records are still bounded by [`MAX_FETCH_COUNT`] alone, so a probe that
/// simply made every batch small would fail here.
#[test]
fn v01_control_byte_ceiling_does_not_shorten_a_batch_that_fits() {
    let (mb, _tmp, clk) = fresh(bulk_cfg());
    let recv = [0x1Au8; 32];
    let sender = [0x5Au8; 32];
    for i in 0..1200u32 {
        let mut cid = [0u8; 32];
        cid[..4].copy_from_slice(&i.to_be_bytes());
        clk.fetch_add(1, Ordering::SeqCst);
        mb.put(recv, cid, sender, vec![0u8; 64]).unwrap();
    }
    let batch = mb.fetch(recv).unwrap();
    assert_eq!(
        batch.len(),
        MAX_FETCH_COUNT,
        "1200 × 64 B is far under the byte ceiling — the RECORD cap is what \
         must bind here"
    );
}
