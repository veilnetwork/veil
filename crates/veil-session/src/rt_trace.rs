//! Bounded session-pipeline tracing for the call-RTT-spike investigation.
//!
//! `DispatcherSink::dispatch` runs SYNCHRONOUSLY on the session task, in
//! the same loop that reads frames off the wire — so every millisecond a
//! bulk frame spends in decrypt/verify/storage delays every frame queued
//! behind it on the ordered stream, including REALTIME call media. The
//! 2026-07-16 campaign eliminated the network, the relay session layer,
//! mailbox drain, every outbound cap and the kernel send buffer; this
//! Besides inbound read/dispatch, the same gate covers sparse outbound
//! probes: slow socket writes and intervals where a queued REALTIME frame
//! cannot enter the already-committed writer channel. This distinguishes
//! priority-queue delay (still reorderable) from TCP/writer head-of-line
//! delay (already beyond the scheduler) without adding timestamps to the
//! protocol or inspecting application payloads.
//!
//! Off by default and free when off (one relaxed atomic load per frame,
//! no `Instant::now`). Enable with `VEIL_RT_TRACE=1` in the environment
//! (relay/CLI deployments) or at runtime through the FFI setter
//! `veil_debug_set_rt_trace` (embedded app nodes, driven by the xVeil
//! debug hook). Only dispatches at/over [`SLOW_DISPATCH_MS`] are logged,
//! so an enabled healthy node stays quiet.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

/// A single inbound dispatch stalling the session loop for this long is
/// worth naming: 25 ms is ~half a video frame interval at 20 fps and far
/// above any healthy handler, yet coarse enough to keep the log sparse.
pub const SLOW_DISPATCH_MS: u128 = 25;

static RT_TRACE: OnceLock<AtomicBool> = OnceLock::new();

fn cell() -> &'static AtomicBool {
    RT_TRACE.get_or_init(|| {
        AtomicBool::new(std::env::var("VEIL_RT_TRACE").is_ok_and(|v| v.trim() == "1"))
    })
}

/// Whether slow-dispatch tracing is on (env `VEIL_RT_TRACE=1` at first
/// check, or [`set_rt_trace`] at any time).
pub fn rt_trace_enabled() -> bool {
    cell().load(Ordering::Relaxed)
}

/// Runtime toggle (FFI/debug-hook path for embedded nodes).
pub fn set_rt_trace(on: bool) {
    cell().store(on, Ordering::Relaxed);
    veil_transport::set_udp_wire_trace(on);
    veil_transport::tcp_trace::set_enabled(on);
}

/// Wall time of a synchronous runner stage, excluding its asynchronous input
/// wait. This names a local scheduling/handler stall, not a network diagnosis.
pub(crate) fn stage_start() -> Option<std::time::Instant> {
    rt_trace_enabled().then(std::time::Instant::now)
}

pub(crate) fn finish_stage(
    started: Option<std::time::Instant>,
    logger: &veil_observability::NodeLogger,
    peer: &[u8; 32],
    stage: &str,
    pq_depth: usize,
) {
    let Some(started) = started else { return };
    let elapsed_us = started.elapsed().as_micros();
    if elapsed_us >= SLOW_DISPATCH_MS * 1000 {
        logger.warn(
            "session.rt_trace.slow_stage",
            format!(
                "peer_id={} stage={stage} elapsed_us={elapsed_us} pq_depth={pq_depth}",
                veil_util::bytes_to_hex(&peer[..4])
            ),
        );
    }
}

/// Bounded per-runner ingress observations. No queue/lifetime/scheduling change:
/// only locally measured age before a frame reaches the priority queue.
#[derive(Default)]
pub(crate) struct IngressTrace {
    counts: [u64; 7],
    max_age_us: [u64; 7],
    last_report: Option<std::time::Instant>,
}
impl IngressTrace {
    pub(crate) fn observe(&mut self, priority: u8, queued_at: std::time::Instant) {
        let index = usize::from(priority.min(6));
        let age = queued_at.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
        if age >= SLOW_DISPATCH_MS as u64 * 1000 {
            self.counts[index] = self.counts[index].saturating_add(1);
            self.max_age_us[index] = self.max_age_us[index].max(age);
        }
    }
    pub(crate) fn report(
        &mut self,
        logger: &veil_observability::NodeLogger,
        peer: &[u8; 32],
        pq_depth: usize,
    ) {
        if self.counts.iter().all(|n| *n == 0) {
            return;
        }
        let now = std::time::Instant::now();
        if self
            .last_report
            .is_some_and(|last| now.saturating_duration_since(last).as_secs() < 1)
        {
            return;
        }
        logger.info(
            "session.rt_trace.aged_ingress",
            format!(
                "peer_id={} aged_frames={:?} max_age_us={:?} pq_depth={pq_depth}",
                veil_util::bytes_to_hex(&peer[..4]),
                self.counts,
                self.max_age_us
            ),
        );
        self.counts = [0; 7];
        self.max_age_us = [0; 7];
        self.last_report = Some(now);
    }
}
