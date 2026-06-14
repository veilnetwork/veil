//! Pure-data state types shared between `FrameDispatcher` and the IPC server.
//!
//! extraction: lifted out of `veilcore::node::dispatcher::mod`
//! so the IPC server can construct / read these structures without depending
//! on dispatcher internals. Three types live here:
//!
//! 1. [`PendingRecursive`] —, DHT recursive-query bookkeeping.
//!    The IPC server registers an entry when it initiates a `FIND_NODE` /
//!    `FIND_VALUE` recursive query; the dispatcher's response handler reads
//!    the entry by `query_id` and fires its `tx` once the response payload
//!    has been parsed and applied to the route cache / value store.
//!
//! 2. [`CaptureEvent`] —, debug-capture frame snapshot. The
//!    dispatcher emits one event per inbound and outbound frame on a
//!    broadcast channel; the IPC `debug capture` handler subscribes and
//!    forwards each event to its connected clients.
//!
//! 3. [`DiagEvent`] —, Pong / TraceHop reply notification. The
//!    dispatcher routes Pong / TraceHop frames to the per-query
//!    `mpsc::Sender<DiagEvent>` registered by the admin-ping / admin-trace
//!    handler.

// ── PendingRecursive ──────────────────────────────────────────────

/// A recursive DHT query awaiting its `RecursiveResponse`.
///
/// The response handler parses `resp.payload` according to `query_type` —
/// populating `route_cache` for `FIND_NODE` / storing the value for
/// `FIND_VALUE` — and then fires `tx` to wake the initiator.
pub struct PendingRecursive {
    /// Target key the query was asked about (used by the response handler
    /// to insert learned peers / values under this key).
    pub target_key: [u8; 32],
    /// One of `veil_proto::routing::recursive_query_type` codes.
    pub query_type: u8,
    /// Signal channel to the initiator — payload bytes are forwarded.
    pub tx: tokio::sync::oneshot::Sender<Vec<u8>>,
}

// ── DiagEvent ──────────────────────────────────────────────────────

/// Event delivered to the pending-ping/trace waiter when a `Pong` or
/// `TraceHop` frame addressed to this node arrives.
#[derive(Debug, Clone)]
pub enum DiagEvent {
    /// A Pong reply arrived. `rtt_us` is sender-measured
    /// (echo_ts_us subtracted from current time by the admin handler).
    Pong {
        responder: [u8; 32],
        echo_ts_us: u64,
    },
    /// A TraceHop reply arrived.
    TraceHop {
        hop_idx: u8,
        node_id: [u8; 32],
        echo_ts_us: u64,
    },
}

// ── CaptureEvent ───────────────────────────────────────────────────

/// max body bytes preserved per `CaptureEvent`.
/// Larger payloads are truncated to this prefix and `body_truncated` set.
/// 256 B is enough to identify the wire structure of any well-known
/// frame type (header + initial bytes of payload — debug-capture is
/// fundamentally a structural-inspection tool, not a replay-fidelity
/// recorder), while bounding memory amplification at 10K pkt/s ×
/// realistic 60 KB chat-node frames from ~600 MB/s to ~2.5 MB/s on
/// the active broadcast channel.
pub const CAPTURE_BODY_PREVIEW_LEN: usize = 256;

/// A single captured frame event emitted by `FrameDispatcher::dispatch`.
#[derive(Debug, Clone)]
pub struct CaptureEvent {
    /// Microseconds since Unix epoch.
    pub ts_us: u64,
    /// Frame arrived from a peer (`true`) or is being sent to a peer (`false`).
    pub inbound: bool,
    /// The peer this frame was received from / sent to.
    pub peer_id: [u8; 32],
    /// The local node's id — used to show src→dst on the CLI.
    pub local_id: [u8; 32],
    pub family: u8,
    pub msg_type: u16,
    pub body_len: u32,
    /// at most `CAPTURE_BODY_PREVIEW_LEN`
    /// bytes of the original frame body. When `body_truncated == true`
    /// `body.len < body_len` — the full payload is NOT recoverable
    /// from the capture stream. This is intentional: debug-capture
    /// runs at hot-path frame dispatch and full-body cloning was
    /// 10 MB/s @ 10K pkt/s → ~600 MB/s broadcast amplification under
    /// chat-node load. The 256 B prefix retains enough structure for
    /// `debug trace` to identify the frame type and initial payload
    /// shape; full-fidelity captures should be done with tcpdump at the
    /// transport layer.
    pub body: Vec<u8>,
    /// `true` if `body` was clipped to
    /// [`CAPTURE_BODY_PREVIEW_LEN`]. Tools surfacing the capture
    /// must indicate truncation — silently displaying a partial body
    /// would misrepresent reality.
    pub body_truncated: bool,
    /// When `true`, `body` contains the **plaintext** application payload
    /// rather than an on-wire OVL1 frame body. Set on the node that performed
    /// E2E encryption (outbound) or decryption (inbound) so `debug capture`
    /// can show both the wire form and the readable content.
    pub e2e_plaintext: bool,
}

/// per-peer rate limit on capture-event
/// emission. 100 events/sec/peer = 100 KB/s of capture output per
/// peer assuming the worst-case 256 B body — across 7 peers under
/// chat-node load that's ~700 KB/s on the broadcast channel
/// down ×60 from the 10 MB/s @ 10K pkt/s pre-fix ceiling.
pub const CAPTURE_PER_PEER_EVENTS_PER_SEC: u32 = 100;

/// Hard cap on the number of per-peer rate-limit windows held in the
/// `CaptureRateLimiter` map. Each entry is ~40 B; 8 192 entries ≈ 320 KiB.
/// The map previously only ever inserted (one entry per distinct peer_id),
/// never reclaiming — bounded in practice by upstream peer caps, but a peer-id
/// flood while capture is active could grow it without limit. At the cap we
/// first drop fully-elapsed windows (lossless — they reset on next touch) and,
/// if still full, evict one arbitrary entry to guarantee room.
pub const CAPTURE_RATE_MAP_CAP: usize = 8_192;

/// simple per-peer rate limiter for
/// capture-event emission. One-second tumbling window. Returns
/// `false` (drop the event) when a peer has hit
/// [`CAPTURE_PER_PEER_EVENTS_PER_SEC`] in the current window;
/// otherwise increments the counter and returns `true`.
///
/// **Why tumbling, not sliding window:** the limiter is a DoS
/// defence, not a fairness primitive. Tumbling is O(1) per call
/// and costs one `Instant::now` + one `HashMap` write; sliding
/// would need a ring buffer per peer. The worst-case under
/// tumbling is a 2× overshoot at the window boundary (peer
/// produces 100 events at t=0.999 + another 100 at t=1.001), which
/// for a debug-capture stream is fine.
///
/// Uses `std::sync::Mutex` rather than tokio's because capture-emit
/// runs on the dispatcher's async hot path BUT only when capture
/// is active (gated by `capture_active` atomic upstream); blocking
/// for a HashMap update is sub-microsecond.
#[derive(Default)]
pub struct CaptureRateLimiter {
    inner: std::sync::Mutex<std::collections::HashMap<[u8; 32], CaptureRateState>>,
}

#[derive(Clone, Copy)]
struct CaptureRateState {
    window_start: std::time::Instant,
    count: u32,
}

impl CaptureRateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check + increment. Returns `true` if caller may proceed
    /// to emit a capture event for `peer_id`; `false` if the peer
    /// has hit the per-second cap and this event must be dropped.
    pub fn allow(&self, peer_id: [u8; 32]) -> bool {
        let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let now = std::time::Instant::now();
        // Bound the map before inserting a NEW peer's window. First drop
        // fully-elapsed windows (lossless — a rolled-over entry resets to
        // count=0 on next touch anyway); if still at the cap under a flood of
        // fresh distinct peer_ids, evict one arbitrary entry to guarantee room.
        if guard.len() >= CAPTURE_RATE_MAP_CAP && !guard.contains_key(&peer_id) {
            guard.retain(|_, st| {
                now.duration_since(st.window_start) < std::time::Duration::from_secs(1)
            });
            if guard.len() >= CAPTURE_RATE_MAP_CAP
                && let Some(&victim) = guard.keys().next()
            {
                guard.remove(&victim);
            }
        }
        let entry = guard.entry(peer_id).or_insert(CaptureRateState {
            window_start: now,
            count: 0,
        });
        if now.duration_since(entry.window_start) >= std::time::Duration::from_secs(1) {
            // Window rolled over — reset.
            entry.window_start = now;
            entry.count = 0;
        }
        if entry.count >= CAPTURE_PER_PEER_EVENTS_PER_SEC {
            return false;
        }
        entry.count += 1;
        true
    }

    /// Test-only sanity check: how many distinct peers currently
    /// have an active rate-limit window? Useful when verifying
    /// that bookkeeping doesn't grow unbounded under workload.
    #[doc(hidden)]
    pub fn tracked_peer_count(&self) -> usize {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).len()
    }
}

impl CaptureEvent {
    /// helper to build a CaptureEvent with body
    /// auto-truncated to [`CAPTURE_BODY_PREVIEW_LEN`]. All call sites
    /// should use this constructor; storing a raw `Vec<u8>` without the
    /// truncation defeats the fix.
    #[allow(clippy::too_many_arguments)] // 9 args matches the wire
    // representation 1:1 (timestamp + direction + 4 IDs + family + msg_type
    // + body len + body). Refactoring to a builder struct would inflate
    // call sites significantly without real type-safety benefit.
    pub fn new_truncated(
        ts_us: u64,
        inbound: bool,
        peer_id: [u8; 32],
        local_id: [u8; 32],
        family: u8,
        msg_type: u16,
        body_len: u32,
        full_body: &[u8],
        e2e_plaintext: bool,
    ) -> Self {
        let truncated = full_body.len() > CAPTURE_BODY_PREVIEW_LEN;
        let body = if truncated {
            full_body[..CAPTURE_BODY_PREVIEW_LEN].to_vec()
        } else {
            full_body.to_vec()
        };
        Self {
            ts_us,
            inbound,
            peer_id,
            local_id,
            family,
            msg_type,
            body_len,
            body,
            body_truncated: truncated,
            e2e_plaintext,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// small body fits in the preview without
    /// truncation; `body_truncated` reflects this honestly.
    #[test]
    fn capture_event_small_body_not_truncated() {
        let small = vec![0xAAu8; 64];
        let ev = CaptureEvent::new_truncated(0, true, [0; 32], [0; 32], 0, 0, 64, &small, false);
        assert_eq!(ev.body, small);
        assert!(!ev.body_truncated);
    }

    /// Body bigger than the preview is clipped to 256 B and flagged.
    #[test]
    fn capture_event_oversize_body_truncated_and_flagged() {
        let big = vec![0xBBu8; 10 * 1024]; // 10 KiB
        let ev = CaptureEvent::new_truncated(0, false, [0; 32], [0; 32], 0, 0, 10_240, &big, false);
        assert_eq!(ev.body.len(), CAPTURE_BODY_PREVIEW_LEN);
        assert!(ev.body_truncated);
        assert_eq!(ev.body_len, 10_240);
        // Prefix bytes preserved.
        assert!(ev.body.iter().all(|&b| b == 0xBB));
    }

    /// Boundary: body of exactly `CAPTURE_BODY_PREVIEW_LEN` does NOT
    /// trigger truncation (the preview captures the whole frame).
    #[test]
    fn capture_event_exact_preview_len_not_truncated() {
        let edge = vec![0xCCu8; CAPTURE_BODY_PREVIEW_LEN];
        let ev = CaptureEvent::new_truncated(
            0,
            true,
            [0; 32],
            [0; 32],
            0,
            0,
            CAPTURE_BODY_PREVIEW_LEN as u32,
            &edge,
            false,
        );
        assert_eq!(ev.body.len(), CAPTURE_BODY_PREVIEW_LEN);
        assert!(!ev.body_truncated);
    }

    /// per-peer rate limiter admits the
    /// first 100 events for a peer in a 1 s window, drops the
    /// 101st.
    #[test]
    fn capture_rate_limiter_caps_at_100_per_peer_per_sec() {
        let limiter = CaptureRateLimiter::new();
        let peer = [0x01u8; 32];
        let mut admitted = 0;
        for _ in 0..150 {
            if limiter.allow(peer) {
                admitted += 1;
            }
        }
        assert_eq!(
            admitted, CAPTURE_PER_PEER_EVENTS_PER_SEC as usize,
            "first 100 must pass; everything past 100 is dropped"
        );
    }

    /// Different peers have independent windows — overflowing one
    /// peer doesn't penalise others.
    #[test]
    fn capture_rate_limiter_isolates_peers() {
        let limiter = CaptureRateLimiter::new();
        let noisy = [0xAAu8; 32];
        let quiet = [0xBBu8; 32];
        // Saturate noisy peer.
        for _ in 0..200 {
            limiter.allow(noisy);
        }
        // Quiet peer still gets all 100 events.
        let quiet_admitted = (0..100).filter(|_| limiter.allow(quiet)).count();
        assert_eq!(quiet_admitted, 100, "quiet peer not penalised by noisy one");
    }

    /// Bookkeeping is per-peer so the tracked-peer count rises with
    /// distinct senders. Doesn't test eviction (the limiter is
    /// only memory-bounded by total active peers, which is itself
    /// bounded by other / 6.48 caps in the dispatcher).
    #[test]
    fn capture_rate_limiter_tracks_distinct_peers() {
        let limiter = CaptureRateLimiter::new();
        for i in 0u8..5 {
            let mut peer = [0u8; 32];
            peer[0] = i;
            assert!(limiter.allow(peer));
        }
        assert_eq!(limiter.tracked_peer_count(), 5);
    }
}
