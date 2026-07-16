//! Slow-inbound-dispatch tracing for the call-RTT-spike investigation.
//!
//! `DispatcherSink::dispatch` runs SYNCHRONOUSLY on the session task, in
//! the same loop that reads frames off the wire — so every millisecond a
//! bulk frame spends in decrypt/verify/storage delays every frame queued
//! behind it on the ordered stream, including REALTIME call media. The
//! 2026-07-16 campaign eliminated the network, the relay session layer,
//! mailbox drain, every outbound cap and the kernel send buffer; this
//! trace exists to confirm (or refute) the one remaining suspect —
//! inbound PROCESSING head-of-line on the session task — and to name the
//! frame kinds responsible.
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
}
