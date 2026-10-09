//! A session codec can use either genuine QUIC datagrams or explicitly
//! negotiated, parent-bound ordered records. This adapter grants no authority
//! and does not label producers, reserve priority or invent transport metrics.

use crate::parallel_binding::BoundOrderedHandle;
use std::time::Instant;
use veil_transport::{QuicDatagramHandle, QuicDatagramSendError};

#[derive(Clone)]
pub(super) enum LossyTransportHandle {
    Quic(QuicDatagramHandle),
    Ordered(BoundOrderedHandle),
}

#[derive(Debug, thiserror::Error)]
pub(super) enum LossySendError {
    #[error("loss-tolerant record too large")]
    TooLarge,
    #[error("loss-tolerant record queue full")]
    Full,
    #[error("loss-tolerant record expired")]
    Expired,
    #[error("loss-tolerant transport unavailable: {0}")]
    Unavailable(String),
}

impl LossySendError {
    /// A single dropped frame does not retire the channel. In particular a
    /// bounded TCP queue cannot be treated as a broken connection or cause
    /// replay of partially admitted fragments on the reliable stream.
    pub(super) fn is_temporary(&self) -> bool {
        matches!(self, Self::Full | Self::Expired)
    }
}

impl From<QuicDatagramSendError> for LossySendError {
    fn from(error: QuicDatagramSendError) -> Self {
        match error {
            QuicDatagramSendError::TooLarge => Self::TooLarge,
            other => Self::Unavailable(other.to_string()),
        }
    }
}

impl From<veil_transport::ordered_records::RecordSendError> for LossySendError {
    fn from(error: veil_transport::ordered_records::RecordSendError) -> Self {
        use veil_transport::ordered_records::RecordSendError;
        match error {
            RecordSendError::TooLarge => Self::TooLarge,
            RecordSendError::Full => Self::Full,
            RecordSendError::Expired => Self::Expired,
            RecordSendError::Closed => Self::Unavailable("ordered child closed".into()),
        }
    }
}

impl From<QuicDatagramHandle> for LossyTransportHandle {
    fn from(handle: QuicDatagramHandle) -> Self {
        Self::Quic(handle)
    }
}

impl From<BoundOrderedHandle> for LossyTransportHandle {
    fn from(handle: BoundOrderedHandle) -> Self {
        Self::Ordered(handle)
    }
}

impl LossyTransportHandle {
    pub(super) fn is_closed(&self) -> bool {
        match self {
            Self::Quic(handle) => handle.is_closed(),
            Self::Ordered(handle) => handle.is_closed(),
        }
    }

    pub(super) fn quic(&self) -> Option<&QuicDatagramHandle> {
        match self {
            Self::Quic(handle) => Some(handle),
            Self::Ordered(_) => None,
        }
    }

    pub(super) fn max_size(&self) -> Option<usize> {
        match self {
            Self::Quic(handle) => handle.max_size(),
            Self::Ordered(handle) => handle.max_size(),
        }
    }

    pub(super) fn send_buffer_space(&self) -> usize {
        match self {
            Self::Quic(handle) => handle.send_buffer_space(),
            Self::Ordered(handle) => handle.send_buffer_space(),
        }
    }

    pub(super) fn queue_charge(&self, payload_bytes: usize) -> usize {
        match self {
            Self::Quic(_) => payload_bytes,
            Self::Ordered(_) => veil_transport::ordered_records::record_queue_charge(payload_bytes),
        }
    }

    pub(super) fn send(&self, payload: &[u8]) -> Result<(), LossySendError> {
        // The same local residence limit applies to every opaque datagram,
        // including transit traffic. No producer/deadline is sent to a relay.
        self.send_before(
            payload,
            Instant::now() + veil_transport::ordered_records::RECORD_RECEIVE_MAX_AGE,
        )
    }

    pub(super) fn send_before(
        &self,
        payload: &[u8],
        expires_at: Instant,
    ) -> Result<(), LossySendError> {
        let expires_at = expires_at
            .min(Instant::now() + veil_transport::ordered_records::RECORD_RECEIVE_MAX_AGE);
        match self {
            Self::Quic(handle) => handle.send_before(payload, expires_at).map_err(Into::into),
            Self::Ordered(handle) => handle.send_before(payload, expires_at).map_err(Into::into),
        }
    }

    pub(super) async fn recv(&self) -> veil_transport::Result<Vec<u8>> {
        match self {
            Self::Quic(handle) => handle.recv().await,
            Self::Ordered(handle) => handle.recv().await.map_err(Into::into),
        }
    }

    /// Genuine per-transport observations. Ordered records report local queue
    /// and flush progress, never fabricated RTT/CWND/ACK/UDP fields.
    pub(super) fn path_trace(&self) -> String {
        match self {
            Self::Quic(handle) => {
                let p = handle.path_stats();
                format!(
                    "transport=quic connection_trace_id={} rtt_us={} cwnd_bytes={} in_flight_bytes={} pto_count={} lost_packets={} congestion_events={} udp_sent={} udp_received={} acks_received={} expired_outgoing_datagrams={} residual_window_transmits={} event_queue_last_us={} event_queue_max_us={} event_queue_stalls={} timer_late_last_us={} timer_late_max_us={} timer_stalls={} udp_send_wait_last_us={} udp_send_wait_max_us={} udp_send_stalls={} udp_send_pending_us={}",
                    handle.local_trace_id(),
                    p.rtt_us,
                    p.congestion_window_bytes,
                    p.in_flight_bytes,
                    p.pto_count,
                    p.lost_packets,
                    p.congestion_events,
                    p.udp_sent,
                    p.udp_received,
                    p.acknowledgments_received,
                    p.expired_outgoing_datagrams,
                    p.residual_window_transmits,
                    p.event_queue_last_us,
                    p.event_queue_max_us,
                    p.event_queue_stalls,
                    p.timer_late_last_us,
                    p.timer_late_max_us,
                    p.timer_stalls,
                    p.udp_send_wait_last_us,
                    p.udp_send_wait_max_us,
                    p.udp_send_stalls,
                    p.udp_send_pending_us,
                )
            }
            Self::Ordered(handle) => {
                let p = handle.progress();
                let active_us = p
                    .active_record_age
                    .map_or_else(|| "none".to_owned(), |age| age.as_micros().to_string());
                format!(
                    "transport=ordered records_reserved_bytes={} record_write_active_us={} records_flushed={} records_expired_outgoing={} records_incoming_bytes={} records_received={} records_evicted_incoming={} records_expired_incoming={}",
                    p.reserved_bytes,
                    active_us,
                    p.completed_records,
                    p.expired_records,
                    p.incoming_buffered_bytes,
                    p.received_records,
                    p.dropped_incoming_records,
                    p.expired_incoming_records,
                )
            }
        }
    }
}
