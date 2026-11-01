//! Opt-in observations before OVL1 can start. No addresses, wire IDs or bytes
//! from a peer are logged. A borrowed connection never extends QUIC ownership.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

static ENABLED: OnceLock<AtomicBool> = OnceLock::new();
static NEXT_ACCEPT: AtomicU64 = AtomicU64::new(1);

fn enabled() -> &'static AtomicBool {
    ENABLED.get_or_init(|| {
        AtomicBool::new(std::env::var("VEIL_RT_TRACE").is_ok_and(|v| v.trim() == "1"))
    })
}

/// Embedded-node twin of the existing VEIL_RT_TRACE gate.
pub fn set_enabled(on: bool) {
    enabled().store(on, Ordering::Relaxed);
}

pub(super) struct AcceptTrace {
    start: Option<Instant>,
    id: u64,
    phase: &'static str,
    outcome: &'static str,
}

impl AcceptTrace {
    pub(super) fn dequeued() -> Self {
        let on = enabled().load(Ordering::Relaxed);
        let trace = Self {
            start: on.then(Instant::now),
            id: if on {
                NEXT_ACCEPT.fetch_add(1, Ordering::Relaxed)
            } else {
                0
            },
            phase: "queued",
            outcome: "cancelled",
        };
        trace.event("begin");
        trace
    }

    pub(super) fn stage(&mut self, phase: &'static str) {
        self.phase = phase;
        self.event("stage");
    }

    pub(super) fn outcome(&mut self, outcome: &'static str) {
        self.outcome = outcome;
    }

    fn event(&self, event: &'static str) {
        if let Some(start) = self.start {
            let outcome = if event == "end" {
                self.outcome
            } else {
                "pending"
            };
            log::info!(
                "quic.accept.stage event={event} accept={} phase={} outcome={} elapsed_us={}",
                self.id,
                self.phase,
                outcome,
                start.elapsed().as_micros(),
            );
        }
    }

    pub(super) fn first_stream<'a>(
        &'a mut self,
        connection: &'a quinn::Connection,
    ) -> FirstStream<'a> {
        self.stage("first_stream");
        let span = FirstStream {
            trace: self,
            connection,
            outcome: "cancelled",
        };
        span.snapshot("begin");
        span
    }
}

impl Drop for AcceptTrace {
    fn drop(&mut self) {
        self.event("end");
    }
}

pub(super) struct FirstStream<'a> {
    trace: &'a mut AcceptTrace,
    connection: &'a quinn::Connection,
    outcome: &'static str,
}

impl FirstStream<'_> {
    pub(super) fn outcome(&mut self, outcome: &'static str) {
        self.outcome = outcome;
        self.trace.outcome(outcome);
    }

    fn snapshot(&self, event: &'static str) {
        if let Some(start) = self.trace.start {
            let outcome = if event == "end" {
                self.outcome
            } else {
                "pending"
            };
            let stats = self.connection.stats();
            let driver = self.connection.driver_stats();
            log::info!(
                "quic.accept.stream event={event} accept={} connection_trace_id={} outcome={} elapsed_us={} udp_rx={} udp_tx={} stream_rx={} stream_tx={} ack_rx={} lost={} pto={} in_flight={} retained={} socket_sent={} timer_late_max_us={} udp_send_wait_max_us={}",
                self.trace.id,
                self.connection.local_trace_id(),
                outcome,
                start.elapsed().as_micros(),
                stats.udp_rx.datagrams,
                stats.udp_tx.datagrams,
                stats.frame_rx.stream,
                stats.frame_tx.stream,
                stats.frame_rx.acks,
                stats.path.lost_packets,
                stats.path.pto_count,
                stats.path.in_flight_bytes,
                stats.path.stream_retained_bytes,
                driver.udp_socket_sent_bytes,
                driver.timer_late_max_us,
                driver.udp_send_wait_max_us,
            );
        }
    }
}

impl Drop for FirstStream<'_> {
    fn drop(&mut self) {
        self.snapshot("end");
    }
}
