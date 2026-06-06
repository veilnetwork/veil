//! SessionRunner decomposition slice 23: cover-traffic padding frame
//! emission.
//!
//! Anti-DPI defence — when the wire has been silent for the cover
//! interval (managed by [`SessionTimers::cover_due_and_reschedule`]),
//! the runner emits а `SessionMsg::Padding` frame с а small random body
//! so the TLS-record size distribution stays close к а normal HTTPS
//! browsing pattern.  Receivers discard `Padding` silently.
//!
//! # Why extracted
//!
//! The inline block was 22 LoC of frame construction + random-body
//! generation + pq.push.  Moving it к а free function reduces SessionRunner.run()'s body, keeps the magic numbers (cover
//! body length range) localised, и makes the cover-shape policy
//! unit-testable без spinning up а full session.
//!
//! # Wire format
//!
//! Frame body: 1..32 random bytes.  `coalesce_with_padding` (one layer
//! up) rounds the wire size к the next TLS bucket anyway, так что the
//! inner length is shape-irrelevant к the DPI signature — но small +
//! variable bytes prevent synthesizing а detectable "always exactly
//! N bytes" cover.
//!
//! # Allocation strategy
//!
//! The builder writes directly into а pooled buffer via
//! `veil_bufpool::global().acquire(...)` и hands back а
//! [`PooledShared`].  The previous shape (`Vec<u8>` → caller
//! `pooled_shared_from_vec(...)`) did 2-3 small heap allocs per cover
//! emission (body Vec + header `[u8; HEADER_SIZE].to_vec()` + extend
//! realloc) и threw them away one frame later when the wire writer
//! dropped the `PooledShared` — pool buckets never saw the allocation.
//! Cover-frame cadence is low (~1/30s/session) so this is not а hot
//! path, но aligning с the surrounding pooled-buffer plumbing removes
//! the dead allocator round-trip и keeps а cluster-wide flame-graph
//! sweep one-shape cleaner (cover/keepalive/ack/data all flow through
//! the same bucket).

use rand_core::{OsRng, RngCore};

use veil_bufpool::PooledShared;
use veil_proto::{
    SessionMsg,
    codec::encode_header,
    family::FrameFamily,
    header::{FrameHeader, HEADER_SIZE},
};

/// Body-length range для cover frames.  See module doc.
pub const MIN_COVER_BODY_LEN: usize = 1;
pub const MAX_COVER_BODY_LEN: usize = 32;

/// Build а cover-traffic padding frame ready к push to the priority
/// queue.  Cheap; idempotent — returns а fresh frame on every call.
/// No side effects, no logging.
///
/// The frame body is `1..=32` random bytes; `OsRng` is the entropy
/// source (compile-time-locked к а cryptographically secure RNG —
/// `rand_core::OsRng` is а thin wrapper over `getrandom` /
/// `BCryptGenRandom`).
///
/// Returns а [`PooledShared`] handle — buffer comes от the global
/// `veil-bufpool` so steady-state cover emission rides the cached
/// bucket с zero allocator traffic after warmup.
pub fn build_cover_frame() -> PooledShared {
    let inner_len = MIN_COVER_BODY_LEN
        + (OsRng.next_u32() as usize % (MAX_COVER_BODY_LEN - MIN_COVER_BODY_LEN + 1));

    let frame_len = HEADER_SIZE + inner_len;
    let mut pooled = veil_bufpool::global().acquire(frame_len);
    let buf = pooled.as_vec_mut();
    debug_assert!(buf.is_empty(), "pool returns empty Vec");

    let mut hdr = FrameHeader::new(FrameFamily::Session as u8, SessionMsg::Padding as u16);
    hdr.body_len = inner_len as u32;
    buf.extend_from_slice(&encode_header(&hdr));

    // Allocate space for the body, then fill in-place to avoid the
    // intermediate `vec![0u8; n]` + `extend_from_slice` two-step.
    let body_start = buf.len();
    buf.resize(frame_len, 0);
    OsRng.fill_bytes(&mut buf[body_start..]);

    pooled.into_shared()
}

#[cfg(test)]
mod tests {
    use super::*;
    use veil_proto::codec::decode_header;

    /// Cover frame must always be а valid Session/Padding frame с
    /// body_len ∈ [MIN, MAX] и а consistent body region size.
    #[test]
    fn cover_frame_decodes_as_session_padding() {
        for _ in 0..100 {
            let frame = build_cover_frame();
            let bytes = frame.as_slice();
            let hdr = decode_header(bytes).expect("decodes");
            assert_eq!(hdr.family, FrameFamily::Session as u8);
            assert_eq!(hdr.msg_type, SessionMsg::Padding as u16);
            assert!(
                (MIN_COVER_BODY_LEN as u32..=MAX_COVER_BODY_LEN as u32).contains(&hdr.body_len)
            );
            assert_eq!(
                bytes.len(),
                HEADER_SIZE + hdr.body_len as usize,
                "frame length must match header + body declarations"
            );
        }
    }

    /// Each call must produce а distinct frame: bodies ара fresh
    /// random bytes, so consecutive calls have indistinguishable
    /// probability of collision (≈ 1/256^min_len).  Test that two
    /// adjacent calls don't return byte-identical frames — а
    /// regression where build_cover_frame got accidentally pinned к
    /// а constant body would fail here within one iteration.
    #[test]
    fn cover_frames_differ_between_calls() {
        let a = build_cover_frame();
        let a_bytes = a.as_slice().to_vec();
        let mut all_match = true;
        for _ in 0..20 {
            let b = build_cover_frame();
            if a_bytes != b.as_slice() {
                all_match = false;
                break;
            }
        }
        assert!(
            !all_match,
            "20 consecutive cover frames were byte-identical; entropy source broken"
        );
    }

    /// Body-length lower bound: `inner_len >= 1` (no zero-length
    /// padding).  Test 1000 iterations covers the edge case where
    /// `OsRng.next_u32() % 32 == 0` (would give `inner_len = 1`, not
    /// 0 — that's the point of `+ MIN`).
    #[test]
    fn cover_body_length_never_zero() {
        for _ in 0..1000 {
            let frame = build_cover_frame();
            let hdr = decode_header(frame.as_slice()).expect("decodes");
            assert!(hdr.body_len >= 1, "cover body must be at least 1 byte");
        }
    }

    /// After warmup, repeated calls must hit the pool cache rather
    /// than fall back к direct heap.  Verifies the alloc-pool refactor
    /// actually engages the bucket reuse path.
    #[test]
    fn cover_frames_hit_pool_after_warmup() {
        // Warmup: prime the bucket с а round-trip allocation.
        for _ in 0..16 {
            drop(build_cover_frame());
        }
        let before = veil_bufpool::global().stats();

        // Steady-state: 32 emissions, each dropped immediately so its
        // buffer returns к the bucket.  Cache-hit count must climb;
        // fallback-alloc count must NOT (otherwise the bucket is being
        // skipped, e.g. mis-sized acquire request).
        for _ in 0..32 {
            drop(build_cover_frame());
        }

        let after = veil_bufpool::global().stats();
        assert!(
            after.cache_hit_total > before.cache_hit_total,
            "cover-frame builder must engage pool cache (cache_hit_total stuck at {})",
            before.cache_hit_total,
        );
        assert_eq!(
            after.fallback_alloc_total, before.fallback_alloc_total,
            "steady-state cover emission must not fall back к direct heap"
        );
    }
}
