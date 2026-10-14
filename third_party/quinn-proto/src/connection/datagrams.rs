use std::collections::VecDeque;

use bytes::Bytes;
use thiserror::Error;
use tracing::{debug, trace};

use super::{Connection, Event};
use crate::{
    frame::{Datagram, FrameStruct},
    Duration, Instant, TransportError,
};

/// API to control datagram traffic
pub struct Datagrams<'a> {
    pub(super) conn: &'a mut Connection,
}

impl Datagrams<'_> {
    /// Queue an unreliable, unordered datagram for immediate transmission
    ///
    /// If `drop` is true, previously queued datagrams which are still unsent may be discarded to
    /// make space for this datagram, in order of oldest to newest. If `drop` is false, and there
    /// isn't enough space due to previously queued datagrams, this function will return
    /// `SendDatagramError::Blocked`. `Event::DatagramsUnblocked` will be emitted once datagrams
    /// have been sent.
    ///
    /// Returns `Err` iff a `len`-byte datagram cannot currently be sent.
    pub fn send(&mut self, data: Bytes, drop: bool) -> Result<(), SendDatagramError> {
        self.send_inner(data, drop, None, None)
    }

    /// Queue a datagram that may not be put into a packet at or after `expires_at`.
    /// The deadline is process-local and is never transmitted to the peer.
    pub fn send_with_expiry(
        &mut self,
        data: Bytes,
        drop: bool,
        expires_at: Instant,
    ) -> Result<(), SendDatagramError> {
        self.send_inner(data, drop, Some(expires_at), None)
    }

    /// Like `send_with_expiry`, with a caller-supplied monotonic enqueue time
    /// for local queue diagnostics. Neither timestamp is sent to the peer.
    pub fn send_with_expiry_at(
        &mut self,
        data: Bytes,
        drop: bool,
        expires_at: Instant,
        queued_at: Instant,
    ) -> Result<(), SendDatagramError> {
        self.send_inner(data, drop, Some(expires_at), Some(queued_at))
    }

    /// Remove expired outgoing datagrams, releasing capacity for fresh data.
    /// Returns the number removed, including zero-length datagrams.
    pub fn expire(&mut self, now: Instant) -> usize {
        let removed = self.conn.datagrams.expire(now);
        if removed > 0 && self.conn.datagrams.send_blocked {
            self.conn.datagrams.send_blocked = false;
            self.conn.events.push_back(Event::DatagramsUnblocked);
        }
        removed
    }

    fn send_inner(
        &mut self,
        data: Bytes,
        drop: bool,
        expires_at: Option<Instant>,
        queued_at: Option<Instant>,
    ) -> Result<(), SendDatagramError> {
        if self.conn.config.datagram_receive_buffer_size.is_none() {
            return Err(SendDatagramError::Disabled);
        }
        let max = self
            .max_size()
            .ok_or(SendDatagramError::UnsupportedByPeer)?;
        if data.len() > max {
            return Err(SendDatagramError::TooLarge);
        }
        if drop {
            while self.conn.datagrams.outgoing_total > self.conn.config.datagram_send_buffer_size {
                let prev = self
                    .conn
                    .datagrams
                    .outgoing
                    .pop_front()
                    .expect("datagrams.outgoing_total desynchronized");
                trace!(len = prev.data.len(), "dropping outgoing datagram");
                self.conn.datagrams.outgoing_total -= prev.data.len();
            }
        } else if self.conn.datagrams.outgoing_total + data.len()
            > self.conn.config.datagram_send_buffer_size
        {
            self.conn.datagrams.send_blocked = true;
            return Err(SendDatagramError::Blocked(data));
        }
        self.conn.datagrams.outgoing_total += data.len();
        self.conn.datagrams.outgoing.push_back(QueuedDatagram {
            datagram: Datagram { data },
            expires_at,
            queued_at,
        });
        if let Some(deadline) = expires_at {
            self.conn.datagrams.next_expiry = Some(
                self.conn
                    .datagrams
                    .next_expiry
                    .map_or(deadline, |held| held.min(deadline)),
            );
        }
        Ok(())
    }

    /// Total unsent outgoing datagrams removed by local expiry, not wire loss.
    pub fn expired_outgoing(&self) -> u64 {
        self.conn.datagrams.expired_outgoing
    }

    /// Longest local wait of a timed datagram actually placed into a packet.
    /// Expired datagrams and datagrams without an enqueue observation are excluded.
    pub fn outgoing_queue_age_max(&self) -> Duration {
        self.conn.datagrams.outgoing_queue_age_max
    }

    /// Compute the maximum size of datagrams that may passed to `send_datagram`
    ///
    /// Returns `None` if datagrams are unsupported by the peer or disabled locally.
    ///
    /// This may change over the lifetime of a connection according to variation in the path MTU
    /// estimate. The peer can also enforce an arbitrarily small fixed limit, but if the peer's
    /// limit is large this is guaranteed to be a little over a kilobyte at minimum.
    ///
    /// Not necessarily the maximum size of received datagrams.
    pub fn max_size(&self) -> Option<usize> {
        // We use the conservative overhead bound for any packet number, reducing the budget by at
        // most 3 bytes, so that PN size fluctuations don't cause users sending maximum-size
        // datagrams to suffer avoidable packet loss.
        let max_size = self.conn.path.current_mtu() as usize
            - self.conn.predict_1rtt_overhead(None)
            - Datagram::SIZE_BOUND;
        let limit = self
            .conn
            .peer_params
            .max_datagram_frame_size?
            .into_inner()
            .saturating_sub(Datagram::SIZE_BOUND as u64);
        Some(limit.min(max_size as u64) as usize)
    }

    /// Receive an unreliable, unordered datagram
    pub fn recv(&mut self) -> Option<Bytes> {
        self.conn.datagrams.recv()
    }

    /// Bytes available in the outgoing datagram buffer
    ///
    /// When greater than zero, [`send`](Self::send)ing a datagram of at most this size is
    /// guaranteed not to cause older datagrams to be dropped.
    pub fn send_buffer_space(&self) -> usize {
        self.conn
            .config
            .datagram_send_buffer_size
            .saturating_sub(self.conn.datagrams.outgoing_total)
    }
}

#[derive(Default)]
pub(super) struct DatagramState {
    /// Number of bytes of datagrams that have been received by the local transport but not
    /// delivered to the application
    pub(super) recv_buffered: usize,
    pub(super) incoming: VecDeque<Datagram>,
    pub(super) outgoing: VecDeque<QueuedDatagram>,
    next_expiry: Option<Instant>,
    expired_outgoing: u64,
    outgoing_queue_age_max: Duration,
    pub(super) outgoing_total: usize,
    pub(super) send_blocked: bool,
}

pub(super) struct QueuedDatagram {
    datagram: Datagram,
    expires_at: Option<Instant>,
    queued_at: Option<Instant>,
}

impl std::ops::Deref for QueuedDatagram {
    type Target = Datagram;
    fn deref(&self) -> &Self::Target {
        &self.datagram
    }
}

impl DatagramState {
    fn expire(&mut self, now: Instant) -> usize {
        if self.next_expiry.map_or(true, |deadline| deadline > now) {
            return 0;
        }
        let before = self.outgoing.len();
        self.next_expiry = None;
        self.outgoing.retain(|packet| {
            if packet.expires_at.is_some_and(|deadline| deadline <= now) {
                self.outgoing_total -= packet.data.len();
                return false;
            }
            if let Some(deadline) = packet.expires_at {
                self.next_expiry =
                    Some(self.next_expiry.map_or(deadline, |held| held.min(deadline)));
            }
            true
        });
        let removed = before - self.outgoing.len();
        self.expired_outgoing = self.expired_outgoing.saturating_add(removed as u64);
        removed
    }

    pub(super) fn received(
        &mut self,
        datagram: Datagram,
        window: &Option<usize>,
    ) -> Result<bool, TransportError> {
        let window = match window {
            None => {
                return Err(TransportError::PROTOCOL_VIOLATION(
                    "unexpected DATAGRAM frame",
                ));
            }
            Some(x) => *x,
        };

        if datagram.data.len() > window {
            return Err(TransportError::PROTOCOL_VIOLATION("oversized datagram"));
        }

        let was_empty = self.recv_buffered == 0;
        while datagram.data.len() + self.recv_buffered > window {
            debug!("dropping stale datagram");
            self.recv();
        }

        self.recv_buffered += datagram.data.len();
        self.incoming.push_back(datagram);
        Ok(was_empty)
    }

    /// Discard outgoing datagrams with a payload larger than `max_payload` bytes
    ///
    /// Used to ensure that reductions in MTU don't get us stuck in a state where we have a datagram
    /// queued but can't send it.
    pub(super) fn drop_oversized(&mut self, max_payload: usize) {
        self.outgoing.retain(|datagram| {
            let result = datagram.data.len() < max_payload;
            if !result {
                trace!(
                    "dropping {} byte datagram violating {} byte limit",
                    datagram.data.len(),
                    max_payload
                );
                self.outgoing_total -= datagram.data.len();
            }
            result
        });
    }

    /// Attempt to write a datagram frame into `buf`, consuming it from `self.outgoing`
    ///
    /// Returns whether a frame was written. At most `max_size` bytes will be written, including
    /// framing.
    pub(super) fn write(&mut self, now: Instant, buf: &mut Vec<u8>, max_size: usize) -> bool {
        let datagram = match self.outgoing.pop_front() {
            Some(x) => x,
            None => return false,
        };

        if buf.len() + datagram.size(true) > max_size {
            // Future work: we could be more clever about cramming small datagrams into
            // mostly-full packets when a larger one is queued first
            self.outgoing.push_front(datagram);
            return false;
        }

        trace!(len = datagram.data.len(), "DATAGRAM");

        self.outgoing_total -= datagram.data.len();
        if let Some(queued_at) = datagram.queued_at {
            self.outgoing_queue_age_max = self
                .outgoing_queue_age_max
                .max(now.saturating_duration_since(queued_at));
        }
        datagram.encode(true, buf);
        true
    }

    pub(super) fn recv(&mut self) -> Option<Bytes> {
        let x = self.incoming.pop_front()?.data;
        self.recv_buffered -= x.len();
        Some(x)
    }
}

/// Errors that can arise when sending a datagram
#[derive(Debug, Error, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum SendDatagramError {
    /// The peer does not support receiving datagram frames
    #[error("datagrams not supported by peer")]
    UnsupportedByPeer,
    /// Datagram support is disabled locally
    #[error("datagram support disabled")]
    Disabled,
    /// The datagram is larger than the connection can currently accommodate
    ///
    /// Indicates that the path MTU minus overhead or the limit advertised by the peer has been
    /// exceeded.
    #[error("datagram too large")]
    TooLarge,
    /// Send would block
    #[error("datagram send blocked")]
    Blocked(Bytes),
}
