//! Local bounded-attempt diagnostics. No untrusted error strings, proofs,
//! exporters, keys or application roles are logged or sent to the receiver.
use super::*;
use std::sync::atomic::AtomicU8;

#[derive(Clone, Copy)]
#[repr(u8)]
pub(super) enum Phase {
    Connect,
    Channel,
    Exporter,
    Begin,
    HelloWrite,
    AckRead,
    AckVerify,
    DatagramCeiling,
    Ready,
}

impl Phase {
    fn label(value: u8) -> &'static str {
        match value {
            0 => "connect",
            1 => "channel",
            2 => "exporter",
            3 => "begin",
            4 => "hello_write",
            5 => "ack_read",
            6 => "ack_verify",
            7 => "datagram_ceiling",
            8 => "ready",
            _ => "unknown",
        }
    }
}

pub(super) struct Attempt {
    logger: Arc<veil_observability::NodeLogger>,
    peer: NodeIdBytes,
    handle: QuicParallelHandle,
    started: std::time::Instant,
    phase: AtomicU8,
    finished: bool,
}

impl Attempt {
    pub(super) fn new(context: &RealtimeReceiverContext, handle: QuicParallelHandle) -> Self {
        Self {
            logger: Arc::clone(&context.logger),
            peer: context.peer_id,
            handle,
            started: std::time::Instant::now(),
            phase: AtomicU8::new(Phase::Connect as u8),
            finished: false,
        }
    }

    pub(super) fn phase(trace: Option<&Self>, phase: Phase) {
        if let Some(trace) = trace {
            trace.phase.store(phase as u8, Ordering::Relaxed);
        }
    }

    pub(super) fn finish(&mut self, result: &'static str, reason: &'static str) {
        self.finished = true;
        self.emit(result, reason);
    }

    fn emit(&self, result: &'static str, reason: &'static str) {
        self.logger.info(
            "session.parallel.recovery_result",
            format!(
                "peer_id={} local_slot={} result={result} reason={reason} phase={} elapsed_ms={} available_slots={}",
                hex_short(&self.peer),
                veil_proto::priority::REALTIME,
                Phase::label(self.phase.load(Ordering::Relaxed)),
                self.started.elapsed().as_millis(),
                self.handle.available_connection_slots(),
            ),
        );
    }
}

impl Drop for Attempt {
    fn drop(&mut self) {
        if !self.finished {
            // Constructed before spawning: cancellation is visible even if
            // the task is aborted before its first poll. The policy separately
            // records an ACK-progress cancellation; other drops include owner
            // retirement and rekey. Neither is a failed authentication claim.
            self.emit("cancelled", "task_cancelled");
        }
    }
}

pub(super) fn connect_failure(error: veil_transport::TransportError) -> &'static str {
    use veil_transport::TransportError;
    match error {
        TransportError::Quic(message) if message == "parallel QUIC connection budget exhausted" => {
            "connection_budget"
        }
        TransportError::Quic(message) if message == "parallel QUIC parent closed" => {
            "parent_closed"
        }
        TransportError::ConnectTimeout(_) => "connect_timeout",
        TransportError::HandshakeTimeout(_) => "handshake_timeout",
        TransportError::Unsupported(_) => "unsupported",
        _ => "connect_error",
    }
}
