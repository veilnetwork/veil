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
    // Tiny per-receiver cap: 100 bytes.
    let cfg = MailboxConfig {
        quota_per_receiver_bytes: 100,
        rate_limit_per_minute: 0, // disable to focus on quota
        ..MailboxConfig::default()
    };
    let (mb, _tmp, _clk) = fresh(cfg);
    let recv = [1u8; 32];

    // 80 bytes — fits.
    let out = mb.put(recv, [1u8; 32], [9u8; 32], vec![0u8; 80]).unwrap();
    assert!(matches!(out, PutOutcome::Stored { .. }));

    // Next 30 bytes — would push to 110 > 100. Reject.
    let out = mb.put(recv, [2u8; 32], [9u8; 32], vec![0u8; 30]).unwrap();
    match out {
        PutOutcome::QuotaPerReceiverExceeded {
            current_bytes,
            cap_bytes,
        } => {
            assert_eq!(current_bytes, 80);
            assert_eq!(cap_bytes, 100);
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
    // Global cap 200 bytes, no per-receiver cap (set very high), no rate limit.
    let cfg = MailboxConfig {
        quota_per_receiver_bytes: u64::MAX,
        quota_global_bytes: 200,
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
        quota_global_bytes: 200,
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
        quota_global_bytes: 50,
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
            assert_eq!(blob_size, 100);
            assert_eq!(cap_bytes, 50);
        }
        other => panic!("expected QuotaGlobalExceeded, got {:?}", other),
    }
}

#[test]
fn t1_4_p1_ack_removes_blob_and_frees_quota() {
    let cfg = MailboxConfig {
        quota_per_receiver_bytes: 100,
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
    assert_eq!(mb.receiver_bytes(recv).unwrap(), 80);

    let removed = mb.ack(recv, cid).unwrap();
    assert!(removed);
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
    assert_eq!(s.total_blob_bytes, 300);
    assert_eq!(s.blob_count, 2);

    mb.ack([1u8; 32], [1u8; 32]).unwrap();
    let s = mb.stats().unwrap();
    assert_eq!(s.total_blob_bytes, 200);
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
        ALGO_ED25519, MailboxCapabilityToken, TOKEN_VERSION, signed_message_for,
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
        version: TOKEN_VERSION,
        issuer_algo: ALGO_ED25519,
        valid_from_unix: valid_from,
        valid_until_unix: valid_until,
        relay_node_id: None,
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
        quota_per_sender_bytes: 100,
        local_node_id: [0u8; 32], // tight cap
        ..MailboxConfig::default()
    };
    let (mb, _tmp, _clk) = fresh(cfg);
    let sender = [0xABu8; 32];
    // Two 60-byte puts from same sender → second exceeds 100 cap.
    let r1 = mb.put([1u8; 32], [b'A'; 32], sender, vec![0; 60]).unwrap();
    assert!(matches!(r1, PutOutcome::Stored { .. }));
    let r2 = mb.put([2u8; 32], [b'B'; 32], sender, vec![0; 60]).unwrap();
    assert!(matches!(
        r2,
        PutOutcome::QuotaPerSenderExceeded {
            current_bytes: 60,
            cap_bytes: 100
        }
    ));
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
        quota_per_sender_bytes: 100,
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
        ALGO_ED25519, MailboxCapabilityToken, TOKEN_VERSION, signed_message_for,
    };
    use ed25519_dalek::{Signer, SigningKey};

    let cfg = MailboxConfig {
        rate_limit_per_minute: 0,
        quota_global_bytes: 250,
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
        version: TOKEN_VERSION,
        issuer_algo: ALGO_ED25519,
        valid_from_unix: valid_from,
        valid_until_unix: valid_until,
        relay_node_id: None,
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
        quota_global_bytes: 150,
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
        quota_global_bytes: 250,
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
        ALGO_ED25519, MailboxCapabilityToken, TOKEN_VERSION, signed_message_for,
    };
    use ed25519_dalek::{Signer, SigningKey};

    let cfg = MailboxConfig {
        rate_limit_per_minute: 0,
        quota_global_bytes: 150,
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
        version: TOKEN_VERSION,
        issuer_algo: ALGO_ED25519,
        valid_from_unix: valid_from,
        valid_until_unix: valid_until,
        relay_node_id: None,
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
